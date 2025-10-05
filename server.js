require("dotenv").config();
const express = require("express");
const app = express();
const session = require("express-session");
const flash = require("connect-flash");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const path = require("path");
const pm2 = require("pm2");
const fs = require("fs");
const { google } = require('googleapis');
const youtube = google.youtube({ version: 'v3', auth: process.env.YOUTUBE_API_KEY });
const http = require('http'); // New Insert
const server = http.createServer(app); // New Insert
const io = require('socket.io')(server); // Update Versi 1.1.11

// ================= DATABASE =================
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync(__dirname + '/global-bundle.pem').toString()
  }

});

// ================= MIDDLEWARE =================
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "secretkey",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Middleware ini memastikan user sudah terautentikasi (login)
function requireLogin(req, res, next) {
    if (req.isAuthenticated()) {
        // Jika user sudah login, lanjutkan ke route berikutnya
        return next();
    }
    // Jika belum login, simpan pesan flash dan redirect ke halaman login
    req.flash('error_msg', 'Anda harus login untuk mengakses halaman ini.');
    res.redirect('/login');
}

// MIDDLEWARE TIP
app.use((req, res, next) => {
    res.locals.user = req.user || null;
      next();
      });

//MIDDLEWARE FLASH MESSAGE
app.use((req, res, next) => {
    // Memastikan variabel 'messages' selalu tersedia di semua template EJS
    // Ini mengumpulkan semua jenis flash message (success_msg, error_msg, etc.)
    res.locals.messages = req.flash();
    
    // Ini adalah fallback untuk halaman lama yang mungkin memanggil success_msg / error_msg langsung
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    
    //
    next();
});

// Middleware global untuk inject saldo ke semua view

app.use(async (req, res, next) => {
  if (req.isAuthenticated()) {
    try {
      const walletRes = await pool.query(
        "SELECT currency, balance FROM users_wallet WHERE user_id=$1",
        [req.user.id]
      );

      let balance_idr = 0;
      let balance_usdt = 0;

      walletRes.rows.forEach(w => {
        if (w.currency === "IDR") balance_idr = w.balance;
        if (w.currency === "USDT") balance_usdt = w.balance;
      });

      // Kirim ke semua template EJS
      res.locals.balance_idr = balance_idr;
      res.locals.balance_usdt = balance_usdt;
    } catch (err) {
      console.error("Wallet middleware error:", err);
      res.locals.balance_idr = 0;
      res.locals.balance_usdt = 0;
    }
  } else {
    // default jika belum login
    res.locals.balance_idr = 0;
    res.locals.balance_usdt = 0;
  }
  next();
});

// --- global locals ---
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg   = req.flash("error_msg");
  res.locals.error       = req.flash("error");
  res.locals.user        = req.user || null;   // <<-- PENTING: supaya views bisa pakai <%= user %>
  next();
});


// Flash globals
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  next();
});

// --- Global Wallet Middleware ---
app.use(async (req, res, next) => {
  try {
    if (req.user && req.user.id) {
      const walletRes = await pool.query(
        "SELECT * FROM users_wallet WHERE user_id=$1 ORDER BY currency ASC",
        [req.user.id]
      );
      res.locals.wallets = walletRes.rows || [];
      res.locals.selectedWallet =
        res.locals.wallets[0] || { currency: "IDR", balance: 0 };
    } else {
      res.locals.wallets = [];
      res.locals.selectedWallet = { currency: "IDR", balance: 0 };
    }
  } catch (err) {
    console.error("Wallet middleware error:", err);
    res.locals.wallets = [];
    res.locals.selectedWallet = { currency: "IDR", balance: 0 };
  }
  next();
});

// Home / ROOT
app.get("/", (req, res) => {
  res.render("index", { title: "Home" });
});

// ================= AUTH =================
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const userRes = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
      if (userRes.rows.length === 0) return done(null, false, { message: "Email tidak ditemukan" });

      const user = userRes.rows[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return done(null, false, { message: "Password salah" });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, res.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// Helpers
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === "admin") return next();
  req.flash("error_msg", "Akses ditolak");
  res.redirect("/dashboard");
}

// ================= GOOGLE AUTH LOGIN/REGISTER/TAUTKAN AKUN GOOGLE ==============
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_REDIRECT_URI,
    passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
    console.log('--- Google Strategy Dimulai ---');
    try {
        const googleId = profile.id;
        console.log('Google ID Diterima:', googleId);

        const { google } = require('googleapis');
        const youtube = google.youtube({ version: 'v3', auth: process.env.YOUTUBE_API_KEY });
        const channelInfo = await youtube.channels.list({ part: 'id', mine: true, access_token: accessToken });
        const youtubeChannelId = channelInfo.data.items[0]?.id;
        console.log('YouTube Channel ID Ditemukan:', youtubeChannelId);
        
        if (!youtubeChannelId) {
            console.log('Proses Gagal: Channel YouTube tidak ditemukan.');
            return done(null, false, { message: 'Channel YouTube tidak ditemukan untuk akun Google ini.' });
        }
        
        let userToAuth = null; // Variabel untuk menyimpan user yang akan diotentikasi

        if (req.user) {
            console.log('Mode: Menautkan Akun untuk User ID:', req.user.id);
            const userId = req.user.id;
            
            const existingGoogleUser = await pool.query("SELECT * FROM users WHERE google_id = $1 AND id != $2", [googleId, userId]);
            if (existingGoogleUser.rows.length > 0) {
                console.log('Proses Gagal: Google ID sudah dipakai user lain.');
                return done(null, false, { message: 'Akun Google ini sudah tertaut ke pengguna lain.' });
            }

            await pool.query("UPDATE users SET google_id = $1, youtube_channel_id = $2 WHERE id = $3", [googleId, youtubeChannelId, userId]);
            
            // Ambil data user terbaru setelah di-update
            const updatedUser = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
            userToAuth = updatedUser.rows[0];

        } else {
            console.log('Mode: Login atau Register');
            const r = await pool.query('SELECT * FROM users WHERE google_id=$1', [googleId]);
            if (r.rows.length === 0) {
                console.log('User tidak ditemukan, membuat user baru...');
                // ... (logika insert user baru)
                 const ins = await pool.query(
                    "INSERT INTO users (username, email, google_id, role, points, youtube_channel_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
                    [profile.displayName, profile.emails?.[0]?.value, googleId, 'user', 0, youtubeChannelId]
                );
                await pool.query("INSERT INTO users_wallet (user_id, currency, balance) VALUES ($1,'IDR',0), ($1,'USDT',0)", [ins.rows[0].id]);
                userToAuth = ins.rows[0];
            } else {
                console.log('User ditemukan dengan ID:', r.rows[0].id);
                userToAuth = r.rows[0];
            }
        }
        
        console.log('Data User yang akan dikirim ke done():', userToAuth);
        console.log('--- Google Strategy Selesai ---');
        return done(null, userToAuth);

    } catch (e) {
        console.error("!!! Google Strategy Error:", e.response ? e.response.data : e.message);
        return done(e);
    }
}));

// ================= GOOGLE AUTH ROUTES =================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email', 'https://www.googleapis.com/auth/youtube.readonly'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', failureFlash: true }),
  (req, res) => res.redirect('/dashboard')
);
app.get('/auth/google/link', ensureAuthenticated, passport.authenticate('google', { scope: ['profile', 'email', 'https://www.googleapis.com/auth/youtube.readonly'] }));


// ================= ROUTES: AUTH =================
app.get("/login", (req, res) => res.render("login", { title: "Login" }));

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      req.flash("error_msg", info.message);
      return res.redirect("/login");
    }
    req.logIn(user, (err) => {
      if (err) return next(err);

      // 🔥 Redirect sesuai role
      if (user.role === "admin") {
        return res.redirect("/admin");
      } else {
        return res.redirect("/dashboard");
      }
    });
  })(req, res, next);
});

app.get("/register", (req, res) => res.render("register", { title: "Register" }));
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      "INSERT INTO users (username, email, password_hash, role, points) VALUES ($1,$2,$3,$4,$5) RETURNING id",
      [username, email, hash, "user", 0]
    );
    const userId = newUser.rows[0].id;

    await pool.query(
      "INSERT INTO users_wallet (user_id, currency, balance) VALUES ($1,'IDR',0), ($1,'USDT',0)",
      [userId]
    );

    req.flash("success_msg", "Registrasi berhasil, silakan login");
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    req.flash("error_msg", "Gagal registrasi");
    res.redirect("/register");
  }
});

app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/login"));
});

// ================= Helpers untuk Wallet =================
async function loadWallets(req) {
  try {
    const res = await pool.query(
      "SELECT * FROM users_wallet WHERE user_id=$1 ORDER BY currency ASC",
      [req.user.id]
    );
    const wallets = res.rows;
    const selectedWallet = wallets[0] || { currency: "IDR", balance: 0 };
    return { wallets, selectedWallet };
  } catch (err) {
    console.error("Wallet load error:", err);
    return { wallets: [], selectedWallet: { currency: "IDR", balance: 0 } };
  }
}

// ================= ROUTES: USER =================
app.get("/dashboard", ensureAuthenticated, async (req, res) => {
  try {
    const { wallets, selectedWallet } = await loadWallets(req);
    res.render("dashboard", {
      title: "Dashboard",
      user: req.user,
      wallets,
      selectedWallet,
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.redirect("/login");
  }
});

// Wallet dinamis
app.get("/wallet/:currency", ensureAuthenticated, async (req, res) => {
  const { currency } = req.params;
  try {
    const walletRes = await pool.query("SELECT * FROM users_wallet WHERE user_id=$1 AND currency=$2", [
      req.user.id,
      currency.toUpperCase(),
    ]);
    if (walletRes.rows.length === 0) {
      req.flash("error_msg", "Wallet tidak ditemukan");
      return res.redirect("/dashboard");
    }

    res.render("wallet", {
      title: `${currency.toUpperCase()} Wallet`,
      user: req.user,
      wallet: walletRes.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.redirect("/dashboard");
  }
});

// ================= ROUTES: USER TASKS (FINAL) =================

// ROUTE 1: GET /tasks (Menampilkan daftar tugas publik)
app.get("/tasks", ensureAuthenticated, async (req, res) => {
    try {
        // PERBAIKAN: Ambil kolom baru (task_type, verification_url)
        const tasksRes = await pool.query(
            "SELECT id, title, description, reward, status, created_at, task_type, verification_url FROM tasks WHERE status='active' ORDER BY created_at DESC"
        );
        
        // Ambil ID tugas yang sudah diselesaikan oleh user (untuk menandai sebagai completed)
        const completedRes = await pool.query(
            "SELECT task_id, status FROM task_completions WHERE user_id = $1 AND (status = 'approved' OR status = 'pending')",
            [req.user.id]
        );
        const completedTaskIds = completedRes.rows.map(row => row.task_id);

        // Map tasks untuk menentukan status completion
        const tasks = tasksRes.rows.map(task => ({
            ...task,
            // Menandai tugas yang sudah diselesaikan/diajukan
            is_completed: completedTaskIds.includes(task.id), 
        }));

        const { wallets, selectedWallet } = await loadWallets(req);

        res.render("tasks", { 
            title: "Tugas", 
            user: req.user, 
            wallets, 
            selectedWallet,
            tasks: tasks 
        });
    } catch (err) {
        console.error("User tasks READ error:", err);
        req.flash("error_msg", "Gagal memuat daftar tugas.");
        res.redirect("/dashboard");
    }
});

// ROUTE 2: POST /tasks/:id/submit (Rute Verifikasi Manual)
app.post("/tasks/:id/submit", ensureAuthenticated, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.id;
    const { proof } = req.body; // proof adalah data bukti dari form

    try {
        // Cek apakah user sudah pernah submit untuk tugas ini (pending atau approved)
        const existing = await pool.query(
            "SELECT id FROM task_completions WHERE user_id=$1 AND task_id=$2 AND (status = 'pending' OR status = 'approved')", 
            [userId, taskId]
        );
        if (existing.rows.length > 0) {
            req.flash("error_msg", "Anda sudah mengirimkan bukti untuk tugas ini atau sudah disetujui.");
            return res.redirect("/tasks");
        }
        
        // Pengecekan: Pastikan tugas ini BUKAN tugas otomatis
        const taskTypeRes = await pool.query("SELECT task_type FROM tasks WHERE id=$1", [taskId]);
        if (taskTypeRes.rows[0]?.task_type !== 'manual') {
             req.flash("error_msg", "Tugas ini adalah tugas Otomatis. Silakan gunakan tautan klaim.");
             return res.redirect("/tasks");
        }
        
        // Masukkan submission baru dengan status 'pending'
        await pool.query(
            "INSERT INTO task_completions (user_id, task_id, proof_data, status) VALUES ($1, $2, $3, 'pending')",
            [userId, taskId, proof]
        );
        req.flash("success_msg", "Bukti berhasil dikirim dan sedang menunggu verifikasi.");
        res.redirect("/tasks");
    } catch (err) {
        console.error("Error submitting task proof:", err);
        req.flash("error_msg", "Gagal mengirim bukti.");
        res.redirect("/tasks");
    }
});

// ROUTE 3: GET /task/verify/:taskId (Rute Verifikasi Otomatis - Click/Subscribe)
// Kode ini sama dengan yang kita sepakati sebelumnya, hanya disinkronkan ke ensureAuthenticated
app.get("/task/verify/:taskId", ensureAuthenticated, async (req, res) => {
    const taskId = req.params.taskId;
    const userId = req.user.id;
    
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        
        // 1. Cek Tugas (Hanya yang bertipe 'link_click' dan 'active')
        const taskRes = await client.query(
            "SELECT reward, verification_url FROM tasks WHERE id = $1 AND status = 'active' AND task_type = 'link_click'", 
            [taskId]
        );
        
        if (taskRes.rows.length === 0) {
            req.flash("error_msg", "Tugas tidak aktif, tidak ditemukan, atau memerlukan verifikasi manual.");
            await client.query("COMMIT");
            return res.redirect("/dashboard");
        }
        const task = taskRes.rows[0];

        // 2. Cek apakah User sudah menyelesaikan Tugas (status 'approved' atau 'completed')
        const completionRes = await client.query(
            "SELECT 1 FROM task_completions WHERE user_id = $1 AND task_id = $2 AND (status = 'approved' OR status = 'completed')",
            [userId, taskId]
        );
        if (completionRes.rows.length > 0) {
            req.flash("warning_msg", "Anda sudah menyelesaikan tugas ini.");
            await client.query("COMMIT");
            return res.redirect(task.verification_url); 
        }

        // 3. LOGIKA PEMBERIAN POIN OTOMATIS
        await client.query("UPDATE users SET points = points + $1 WHERE id = $2", [task.reward, userId]);
        await client.query(
            "INSERT INTO task_completions (user_id, task_id, status) VALUES ($1, $2, 'approved')", // Langsung set status 'approved'
            [userId, taskId]
        );
        
        await client.query("COMMIT");
        
        req.flash("success_msg", `Berhasil! Anda mendapatkan ${task.reward} Poin.`);
        return res.redirect(task.verification_url); 

    } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error verifikasi tugas otomatis:", err);
        req.flash("error_msg", "Terjadi kesalahan saat memproses tugas.");
        return res.redirect("/dashboard");
    } finally {
        client.release();
    }
});

// ROUTES VERIFKASI TUGAS //
// Rute untuk user submit bukti
app.post("/tasks/:id/submit", ensureAuthenticated, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.id;
    const { proof } = req.body;

    try {
        // Cek apakah user sudah pernah submit untuk tugas ini
        const existing = await pool.query("SELECT id FROM task_completions WHERE user_id=$1 AND task_id=$2", [userId, taskId]);
        if (existing.rows.length > 0) {
            req.flash("error_msg", "Anda sudah mengirimkan bukti untuk tugas ini.");
            return res.redirect("/tasks");
        }
        
        await pool.query(
            "INSERT INTO task_completions (user_id, task_id, proof_data) VALUES ($1, $2, $3)",
            [userId, taskId, proof]
        );
        req.flash("success_msg", "Bukti berhasil dikirim dan sedang menunggu verifikasi.");
        res.redirect("/tasks");
    } catch (err) {
        console.error("Error submitting task proof:", err);
        req.flash("error_msg", "Gagal mengirim bukti.");
        res.redirect("/tasks");
    }
});

// --- Rute Admin untuk Verifikasi ---
app.get("/admin/verifications", requireAdmin, async (req, res) => {
    try {
        const submissionsRes = await pool.query(`
            SELECT tc.id, u.username, t.title as task_title, tc.proof_data, tc.completed_at
            FROM task_completions tc
            JOIN users u ON tc.user_id = u.id
            JOIN tasks t ON tc.task_id = t.id
            WHERE tc.status = 'pending'
            ORDER BY tc.completed_at ASC
        `);
        res.render("admin/verifications", {
            title: "Verifikasi Tugas",
            user: req.user,
            submissions: submissionsRes.rows
        });
    } catch (err) {
        console.error("Admin verifications error:", err);
        res.redirect("/admin/dashboard");
    }
});

// Rute admin untuk MENYETUJUI tugas
app.post("/admin/verifications/:id/approve", requireAdmin, async (req, res) => {
    const completionId = req.params.id;
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        
        const completionRes = await client.query("SELECT * FROM task_completions WHERE id = $1 AND status = 'pending' FOR UPDATE", [completionId]);
        if (completionRes.rows.length === 0) {
            await client.query("ROLLBACK");
            req.flash("error_msg", "Pengajuan tidak ditemukan atau sudah diproses.");
            return res.redirect("/admin/verifications");
        }
        const { user_id, task_id } = completionRes.rows[0];

        const taskRes = await client.query("SELECT reward FROM tasks WHERE id = $1", [task_id]);
        const { reward } = taskRes.rows[0];

        await client.query("UPDATE users SET points = points + $1 WHERE id = $2", [reward, user_id]);
        await client.query("UPDATE task_completions SET status = 'approved' WHERE id = $1", [completionId]);
        await client.query("INSERT INTO point_history (user_id, reward, points, status) VALUES ($1, $2, $3, 'success')", [user_id, `Menyelesaikan tugas #${task_id}`, reward]);

        await client.query("COMMIT");
        req.flash("success_msg", "Tugas berhasil disetujui, poin telah ditambahkan.");
        res.redirect("/admin/verifications");
    } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error approving task:", err);
        req.flash("error_msg", "Gagal menyetujui tugas.");
        res.redirect("/admin/verifications");
    } finally {
        client.release();
    }
});

// Rute admin untuk MENOLAK tugas
app.post("/admin/verifications/:id/reject", requireAdmin, async (req, res) => {
    try {
        await pool.query("UPDATE task_completions SET status = 'rejected' WHERE id = $1 AND status = 'pending'", [req.params.id]);
        req.flash("success_msg", "Pengajuan tugas telah ditolak.");
        res.redirect("/admin/verifications");
    } catch (err) {
        console.error("Error rejecting task:", err);
        req.flash("error_msg", "Gagal menolak tugas.");
        res.redirect("/admin/verifications");
    }
});
// ================= ROUTES: USER RAFFLES =================

// List raffles aktif
app.get("/raffles", ensureAuthenticated, async (req, res) => {
  try {
    const rafflesRes = await pool.query(
      "SELECT * FROM raffles WHERE status = 'active' ORDER BY created_at DESC"
    );

    const myTicketsRes = await pool.query(
        `SELECT re.*, r.title as raffle_title 
         FROM raffle_entries re
         JOIN raffles r ON re.raffle_id = r.id
         WHERE re.user_id = $1 
         ORDER BY re.created_at DESC`,
        [req.user.id]
    );

        const winnersRes = await pool.query(
        `SELECT r.reward, u.username 
         FROM raffles r 
         JOIN users u ON r.winner_id = u.id 
         WHERE r.winner_id IS NOT NULL 
         ORDER BY r.draw_date DESC`
    );
    
    res.render("raffles", {
      title: "Raffles",
      user: req.user,
      raffles: rafflesRes.rows,
      myTickets: myTicketsRes.rows,
      winners: winnersRes.rows,
      wallets: [], // kalau perlu tampilkan wallet
    });
  } catch (err) {
    console.error("User raffles error:", err);
    res.render("raffles", {
      title: "Raffles",
      user: req.user,
      raffles: [],
      myTickets: [],
      winners: [],
      wallets: [],
    });
  }
});

// Ikut raffle (tukar point jadi tiket)
app.post("/raffles/:id/join", ensureAuthenticated, async (req, res) => {
  const raffleId = req.params.id;
  const userId = req.user.id;

  try {
    // Ambil saldo point user
    const userRes = await pool.query("SELECT points FROM users WHERE id=$1", [userId]);
    const userPoints = parseInt(userRes.rows[0].points || 0);

    if (userPoints < 100) {
      req.flash("error_msg", "Point Anda tidak cukup (minimal 100).");
      return res.redirect("/raffles");
    }

    // Hitung nomor tiket terakhir untuk raffle ini
    const lastTicketRes = await pool.query(
      "SELECT MAX(ticket_number) AS last_ticket FROM raffle_entries WHERE raffle_id=$1",
      [raffleId]
    );
    const nextTicket = (lastTicketRes.rows[0].last_ticket || 0) + 1;

    // Kurangi 100 point user
    await pool.query("UPDATE users SET points = points - 100 WHERE id=$1", [userId]);

    // Masukkan entry raffle baru
    await pool.query(
      "INSERT INTO raffle_entries (raffle_id, user_id, ticket_number) VALUES ($1,$2,$3)",
      [raffleId, userId, nextTicket]
    );

    req.flash("success_msg", `Anda berhasil ikut raffle dengan tiket #${nextTicket}`);
    res.redirect("/raffles");
  } catch (err) {
    console.error("Join raffle error:", err);
    req.flash("error_msg", "Gagal ikut raffle. Coba lagi.");
    res.redirect("/raffles");
  }
});

// ================= ROUTES: TUKAR-POINT (FINAL) =================

// Memproses form penukaran poin ke tiket raffle (FINAL FIX for GET route)
app.get("/tukar-point", ensureAuthenticated, async (req, res) => {
    let history = []; // Deklarasikan history
    const client = await pool.connect();
    
    try {
        // Ambil riwayat poin untuk user yang sedang login (Hanya 5 item terbaru)
        // Kita gunakan SELECT yang sudah dimodifikasi agar tidak crash jika 'reward' atau 'description' salah.
        const historyRes = await client.query(
            // Asumsi point_history punya kolom 'points' dan 'reward'
            "SELECT created_at, reward, points FROM point_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5",
            [req.user.id]
        );
        history = historyRes.rows;

        // Render halaman dengan data yang aman
        res.render("tukar-point", {
            title: "Tukar Poin",
            user: req.user,
            history: history, // Array history yang sudah dibersihkan
            // Kirim variabel fallback yang dibutuhkan oleh header/partial jika ada
            wallets: [], 
            selectedWallet: { currency: "IDR", balance: 0 }
        });
        
    } catch (err) {
        // Jika terjadi error SQL, kita log dan redirect ke dashboard, TIDAK hang.
        console.error("Error loading tukar-point page:", err.message);
        req.flash("error_msg", "Gagal memuat halaman penukaran poin. Error DB.");
        res.redirect("/dashboard");
    } finally {
        client.release(); // PENTING: Pastikan client dilepaskan
    }
});

// Memproses form penukaran poin ke tiket raffle (FINAL FIX for POST route)
app.post("/tukar-point", ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;
    const { jumlah } = req.body;
    const pointsToExchange = parseInt(jumlah);

    // --- Validasi Input ---
    const rasioTiket = 100;
    const ticketCount = pointsToExchange / rasioTiket;

    if (!pointsToExchange || pointsToExchange < rasioTiket || pointsToExchange % rasioTiket !== 0) {
        req.flash("error_msg", "Jumlah poin harus dalam kelipatan 100.");
        return res.redirect("/tukar-point");
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN"); // START TRANSAKSI

        // 1. Cek Saldo dan Raffle Aktif
        const userRes = await client.query("SELECT points FROM users WHERE id = $1 FOR UPDATE", [userId]);
        const userPoints = parseInt(userRes.rows[0].points);
        
        if (userPoints < pointsToExchange) {
            await client.query("ROLLBACK");
            req.flash("error_msg", "Saldo poin tidak mencukupi.");
            return res.redirect("/tukar-point");
        }
        
        const raffleRes = await client.query("SELECT id FROM raffles WHERE status = 'active' ORDER BY created_at DESC LIMIT 1");
        if (raffleRes.rows.length === 0) {
            await client.query("ROLLBACK");
            req.flash("error_msg", "Saat ini tidak ada raffle yang aktif untuk diikuti.");
            return res.redirect("/tukar-point");
        }
        const raffleId = raffleRes.rows[0].id;

        // 2. Ambil Nomor Tiket Terakhir
        const lastTicketRes = await client.query(
            "SELECT MAX(ticket_number) AS last_ticket FROM raffle_entries WHERE raffle_id=$1",
            [raffleId]
        );
        let nextTicketNumber = (parseInt(lastTicketRes.rows[0].last_ticket) || 0) + 1;
        
        // 3. Kurangi Poin User (CRITICAL STEP)
        await client.query("UPDATE users SET points = points - $1 WHERE id = $2", [pointsToExchange, userId]);
        
        // 4. Catat di Riwayat Poin
        await client.query(
            "INSERT INTO point_history (user_id, reward, points, status) VALUES ($1, $2, $3, $4)",
            [userId, `Tukar ${pointsToExchange} poin ke tiket raffle`, -pointsToExchange, "success"]
        );

        // 5. Buat Tiket Raffle (Loop dan Insert) - Sinkronisasi Ticket Number
        for (let i = 0; i < ticketCount; i++) {
            await client.query(
                "INSERT INTO raffle_entries (raffle_id, user_id, ticket_number) VALUES ($1, $2, $3)",
                [raffleId, userId, nextTicketNumber]
            );
            nextTicketNumber++; // WAJIB: Naikkan nomor tiket
        }

        await client.query("COMMIT"); // COMMIT TRANSAKSI
        
        req.flash("success_msg", `Berhasil menukar ${pointsToExchange} poin dengan ${ticketCount} tiket raffle!`);
        res.redirect("/tukar-point");

    } catch (err) {
        await client.query("ROLLBACK"); // ROLLBACK jika ada error SQL
        console.error("Error transaksi penukaran poin:", err);
        
        // Cek error khusus Foreign Key (jika tabel tidak sinkron)
        if (err.code === '23503') {
            req.flash("error_msg", "Gagal menukar. Raffle atau User tidak valid.");
        } else {
            req.flash("error_msg", "Gagal memproses penukaran. Error sistem.");
        }
        res.redirect("/tukar-point");
    } finally {
        client.release(); // PENTING: Lepaskan client database
    }
});

// ================= ROUTES: CLAIM CODE =================
app.post("/claim-code", ensureAuthenticated, async (req, res) => {
  const { code } = req.body;
  const userId = req.user.id;
  
  if (!code) {
    return res.status(400).json({ success: false, message: "Kode tidak boleh kosong." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const codeRes = await client.query("SELECT * FROM claim_codes WHERE code = $1 AND status = 'active'", [code.toUpperCase()]);
    if (codeRes.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, message: "Kode tidak valid atau tidak aktif." });
    }
    const codeRow = codeRes.rows[0];

    const usedRes = await client.query("SELECT 1 FROM claim_code_redemptions WHERE code_id=$1 AND user_id=$2", [codeRow.id, userId]);
    if (usedRes.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(409).json({ success: false, message: "Anda sudah menggunakan kode ini." });
    }

    await client.query("UPDATE users SET points = points + $1 WHERE id=$2", [codeRow.reward, userId]);
    await client.query("INSERT INTO claim_code_redemptions (code_id, user_id) VALUES ($1, $2)", [codeRow.id, userId]);
    
    // Catat juga di point_history agar muncul di dasbor
    await client.query(
      "INSERT INTO point_history (user_id, reward, points, status) VALUES ($1,$2,$3,$4)",
      [userId, `Klaim kode ${codeRow.code}`, codeRow.reward, "success"]
    );

    await client.query("COMMIT");
    res.json({ success: true, message: `Selamat! Anda mendapatkan ${codeRow.reward} poin.` });

  } catch (err) {
    await client.query("ROLLBACK").catch(()=>{});
    console.error("Claim-code error:", err);
    res.status(500).json({ success: false, message: "Terjadi kesalahan di server." });
  } finally {
    client.release();
  }
});

// ================= ROUTES RIWAYAT (FINAL FIX 2.0) =================
app.get("/history", ensureAuthenticated, async (req, res) => {
    let history = [];
    const client = await pool.connect();
    
    try {
        const consolidationQuery = `
            -- 1. RIWAYAT PERUBAHAN POIN (Tukar, Klaim, dll.)
            SELECT 
                id, 
                created_at, 
                reward AS description, -- PERBAIKAN: Menggunakan 'reward' sebagai deskripsi
                points AS change_amount, 
                'POINT' AS type
            FROM point_history
            WHERE user_id = $1
            
            UNION ALL
            
            -- 2. RIWAYAT PENYELESAIAN TUGAS (Mengambil Reward dari tasks)
            SELECT 
                tc.id, 
                tc.completed_at AS created_at, 
                t.title AS description,
                CASE 
                    WHEN tc.status = 'approved' THEN t.reward
                    ELSE 0 
                END AS change_amount,
                CASE 
                    WHEN tc.status = 'approved' THEN 'TASK_APPROVED'
                    WHEN tc.status = 'rejected' THEN 'TASK_REJECTED'
                    ELSE 'TASK_PENDING'
                END AS type
            FROM task_completions tc
            JOIN tasks t ON tc.task_id = t.id
            WHERE tc.user_id = $1
            
            ORDER BY created_at DESC;
        `;
        
        const historyRes = await client.query(consolidationQuery, [req.user.id]);
        history = historyRes.rows;

    } catch (err) {
        console.error("History error (FINAL DIAGNOSIS):", err.message);
        req.flash("error_msg", "Gagal memuat riwayat aktivitas. Error DB.");
        return res.redirect("/dashboard");
    } finally {
        client.release();
    }

    res.render("history", {
        title: "Riwayat Aktivitas",
        user: req.user,
        history: history,
        wallets: res.locals.wallets,
        selectedWallet: res.locals.selectedWallet
    });
});

// ================= ROUTES: TIP ===================
// GET: Menampilkan halaman Tip dan riwayatnya
app.get("/tip", ensureAuthenticated, async (req, res) => {
    try {
        // Ambil riwayat tip di mana user adalah pengirim ATAU penerima
        const historyRes = await pool.query(
            `SELECT 
                th.*, 
                sender.username AS sender_username, 
                recipient.username AS recipient_username 
            FROM tip_history th
            JOIN users sender ON th.sender_id = sender.id
            JOIN users recipient ON th.recipient_id = recipient.id
            WHERE th.sender_id = $1 OR th.recipient_id = $1
            ORDER BY th.created_at DESC LIMIT 20`,
            [req.user.id]
        );

        res.render("tip", {
            title: "Kirim Tip", // Ini akan membuat link 'Tip' aktif di header
            user: req.user,
            history: historyRes.rows
        });
    } catch (err) {
        console.error("Error loading tip page:", err);
        req.flash("error_msg", "Gagal memuat halaman tip.");
        res.redirect("/dashboard");
    }
});

// POST: Memproses transaksi Tip
app.post("/tip", ensureAuthenticated, async (req, res) => {
    const { username_penerima, jumlah_point } = req.body;
    const senderId = req.user.id;
    const amount = parseInt(jumlah_point);
    const client = await pool.connect();

    try {
        // Validasi Input
        if (!username_penerima || !amount || amount <= 0) {
            req.flash("error_msg", "Username dan jumlah poin harus diisi dengan benar.");
            return res.redirect("/tip");
        }

        if (req.user.username.toLowerCase() === username_penerima.toLowerCase()) {
            req.flash("error_msg", "Anda tidak bisa mengirim tip ke diri sendiri.");
            return res.redirect("/tip");
        }

        await client.query("BEGIN");

        // Cek saldo pengirim & dapatkan ID penerima
        const senderRes = await client.query("SELECT points FROM users WHERE id = $1 FOR UPDATE", [senderId]);
        const recipientRes = await client.query("SELECT id FROM users WHERE username = $1", [username_penerima]);

        if (recipientRes.rows.length === 0) {
            await client.query("ROLLBACK");
            req.flash("error_msg", "Pengguna tidak ditemukan.");
            return res.redirect("/tip");
        }
        
        if (senderRes.rows[0].points < amount) {
            await client.query("ROLLBACK");
            req.flash("error_msg", "Poin Anda tidak cukup.");
            return res.redirect("/tip");
        }

        const recipientId = recipientRes.rows[0].id;
        
        // Lakukan transaksi
        await client.query("UPDATE users SET points = points - $1 WHERE id = $2", [amount, senderId]);
        await client.query("UPDATE users SET points = points + $1 WHERE id = $2", [amount, recipientId]);
        await client.query("INSERT INTO tip_history (sender_id, recipient_id, amount) VALUES ($1, $2, $3)", [senderId, recipientId, amount]);

        await client.query("COMMIT");

        req.flash("success_msg", `Anda berhasil mengirim ${amount} poin ke ${username_penerima}!`);
        res.redirect("/tip");

    } catch (err) {
        await client.query("ROLLBACK").catch(()=>{});
        console.error("Tip transaction error:", err);
        req.flash("error_msg", "Terjadi kesalahan. Transaksi dibatalkan.");
        res.redirect("/tip");
    } finally {
        client.release();
    }
});

// ================= ROUTES: ADMIN =================
// ROUTE 1: REDIRECT /admin -> /admin/dashboard
// Ini mengarahkan user dari URL pendek /admin ke dashboard utama.
app.get("/admin", requireAdmin, (req, res) => {
    // Pastikan user adalah admin, lalu redirect
    res.redirect("/admin/dashboard");
});

// Dashboard Utama

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
    let stats = { totalUsers: 0, activeTasks: 0, activeRaffles: 0, totalWallets: 0 };
    let recentActivity = { rows: [] };
    
    try {
        // Fetch semua data count
        const totalUsersRes = await pool.query("SELECT COUNT(*) FROM users");
        const activeTasksRes = await pool.query("SELECT COUNT(*) FROM tasks WHERE status='active'");
        const activeRafflesRes = await pool.query("SELECT COUNT(*) FROM raffles WHERE status='active'");
        const totalWalletsRes = await pool.query("SELECT COUNT(*) FROM users_wallet");

        // Simpan hasil ke objek stats
        stats = {
            totalUsers: totalUsersRes.rows[0].count,
            activeTasks: activeTasksRes.rows[0].count,
            activeRaffles: activeRafflesRes.rows[0].count,
            totalWallets: totalWalletsRes.rows[0].count,
        };

        // Ambil aktivitas terbaru
        try {
            recentActivity = await pool.query(
                "SELECT description, created_at FROM activity_log ORDER BY created_at DESC LIMIT 5"
            );
        } catch (err) {
            console.warn("activity_log table not found, skip recentActivity");
        }

        res.render("admin/dashboard", {
            title: "Dashboard",
            user: req.user,
            stats: stats, // Objek stats dikirim
            recentActivity: recentActivity.rows,
        });

    } catch (err) {
        console.error("dashboard error:", err);
        // Jika ada error DB, tetap render dengan nilai default (0)
        res.render("admin/dashboard", {
            title: "Admin Dashboard",
            user: req.user,
            stats: stats, // Objek stats default dikirim
            recentActivity: [],
        });
    }
});

// ================= ROUTES: ADMIN USER MANAGEMENT =================

// ROUTE 1: GET /admin/users (Menampilkan Daftar User)
app.get("/admin/users", requireAdmin, async (req, res) => {
    try {
        const usersRes = await pool.query(
            "SELECT id, username, email, points, created_at, is_banned FROM users ORDER BY created_at DESC"
        );
        res.render("admin/users", {
            title: "Kelola Pengguna",
            user: req.user,
            users: usersRes.rows,
        });
    } catch (err) {
        console.error("Admin users error:", err);
        req.flash("error_msg", "Gagal memuat daftar pengguna.");
        res.redirect("/admin/dashboard");
    }
});

//Update Notif//
// ROUTE 2: POST /admin/user/:id/tip-point (Memberi/Mengurangi Poin)
app.post("/admin/user/:id/tip-point", requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const { amount } = req.body;
    const amountInt = parseInt(amount);

    // 1. VALIDASI (Harus di awal)
    if (isNaN(amountInt) || amountInt === 0) {
        req.flash("error_msg", "Jumlah poin tidak valid.");
        return res.redirect("/admin/users");
    }

    const action = amountInt > 0 ? 'menambahkan' : 'mengurangi';

    try {
        // 2. QUERY DATABASE (CRITICAL STEP)
        const result = await pool.query(
            "UPDATE users SET points = points + $1 WHERE id = $2 RETURNING points", // Gunakan RETURNING untuk cek
            [amountInt, userId]
        );
        
        // 3. NOTIFIKASI & FLASH MESSAGE (Hanya jika query berhasil)
        const finalMessage = `Anda baru saja menerima ${amountInt} Poin dari Admin!`;
        
        // Notifikasi Real-Time ke user target
        io.emit('user_tipped', {
            userId: userId, 
            amount: amountInt,
            message: finalMessage
        });
        
        // Notifikasi Flash untuk Admin
        req.flash("success_msg", `Berhasil ${action} ${Math.abs(amountInt)} poin kepada user ID ${userId}.`);
        res.redirect("/admin/users");
        
    } catch (err) {
        // 4. PENANGANAN ERROR
        console.error("Tip point error:", err);
        req.flash("error_msg", "Gagal memperbarui poin.");
        res.redirect("/admin/users");
    }
});

// ROUTE 3: POST /admin/user/ban (Ban/Unban User)
app.post("/admin/user/:id/ban", requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const { action } = req.body; // 'ban' atau 'unban'
    const isBanned = (action === 'ban');

    try {
        await pool.query(
            "UPDATE users SET is_banned = $1 WHERE id = $2",
            [isBanned, userId]
        );
        req.flash("success_msg", `Pengguna berhasil di${action}d.`);
        res.redirect("/admin/users");
    } catch (err) {
        console.error("Ban user error:", err);
        req.flash("error_msg", "Gagal memperbarui status ban.");
        res.redirect("/admin/users");
    }
});

// Catatan: Route Kirim Message membutuhkan integrasi sistem chat/DM yang lebih kompleks (di luar scope awal ini). 
// Untuk saat ini, kita fokus pada fitur Poin dan Banned.

// ================= ROUTES: ADMIN TASKS (FINAL) =================

// ROUTE 1: Daftar tugas (READ) - Memastikan semua kolom diambil
app.get("/admin/tasks", requireAdmin, async (req, res) => {
    try {
        // Ambil semua kolom, termasuk kolom baru untuk ditampilkan di EJS
        const tasksRes = await pool.query(
            "SELECT id, title, description, reward, status, created_at, task_type, verification_url FROM tasks ORDER BY created_at DESC"
        );
        res.render("admin/tasks", {
            title: "Kelola Tugas",
            user: req.user,
            tasks: tasksRes.rows
        });
    } catch (err) {
        console.error("Admin tasks READ error:", err.message);
        // Penting: Jika terjadi error SQL, kita hanya render array kosong
        req.flash("error_msg", "Gagal memuat daftar tugas. Pastikan kolom DB sudah lengkap.");
        res.render("admin/tasks", { title: "Kelola Tugas", user: req.user, tasks: [] });
    }
});

// ROUTE 2: Form tambah tugas (GET NEW)
app.get("/admin/tasks/new", requireAdmin, (req, res) => {
    res.render("admin/tasks-form", {
        title: "Tambah Tugas",
        user: req.user,
        task: null
    });
});

// ROUTE 3: Proses tambah tugas (CREATE) - Menangani nilai NULL/default
app.post("/admin/tasks/new", requireAdmin, async (req, res) => {
    // Ambil semua data dari form
    const { title, description, reward, status, task_type, verification_url } = req.body;

    // Set nilai default/NULL yang diperlukan PostgreSQL
    const finalTaskType = task_type || 'manual'; // Default ke 'manual' jika kosong
    // Jika verification_url kosong di form, kirim NULL ke DB (penting)
    const finalVerificationUrl = verification_url || null; 

    try {
        await pool.query(
            "INSERT INTO tasks (title, description, reward, status, task_type, verification_url) VALUES ($1, $2, $3, $4, $5, $6)",
            [title, description, reward, status, finalTaskType, finalVerificationUrl]
        );
        req.flash("success_msg", "Tugas berhasil ditambahkan.");
        res.redirect("/admin/tasks");
    } catch (err) {
        console.error("Tambah tugas error:", err.message);
        req.flash("error_msg", "Gagal menambahkan tugas. Error SQL: " + err.message);
        res.redirect("/admin/tasks/new");
    }
});

// ROUTE 4: Form edit tugas (GET EDIT) - Mengambil kolom baru
app.get("/admin/tasks/:id/edit", requireAdmin, async (req, res) => {
    try {
        const taskRes = await pool.query("SELECT * FROM tasks WHERE id=$1", [req.params.id]);
        if (taskRes.rows.length === 0) {
            req.flash("error_msg", "Tugas tidak ditemukan.");
            return res.redirect("/admin/tasks");
        }
        res.render("admin/tasks-form", {
            title: "Edit Tugas",
            user: req.user,
            task: taskRes.rows[0]
        });
    } catch (err) {
        console.error("Edit tugas error:", err.message);
        req.flash("error_msg", "Gagal memuat form edit tugas.");
        res.redirect("/admin/tasks");
    }
});

// ROUTE 5: Proses edit tugas (UPDATE) - Memperbarui kolom baru
app.post("/admin/tasks/:id/edit", requireAdmin, async (req, res) => {
    const { title, description, reward, status, task_type, verification_url } = req.body;

    const finalTaskType = task_type || 'manual';
    const finalVerificationUrl = verification_url || null; 
    
    try {
        await pool.query(
            "UPDATE tasks SET title=$1, description=$2, reward=$3, status=$4, task_type=$5, verification_url=$6 WHERE id=$7",
            [title, description, reward, status, finalTaskType, finalVerificationUrl, req.params.id]
        );
        req.flash("success_msg", "Tugas berhasil diperbarui.");
        res.redirect("/admin/tasks");
    } catch (err) {
        console.error("Update tugas error:", err.message);
        req.flash("error_msg", "Gagal memperbarui tugas.");
        res.redirect(`/admin/tasks/${req.params.id}/edit`);
    }
});

// ROUTE 6: Hapus tugas (DELETE)
// POST: Hapus tugas (DELETE)
app.post("/admin/tasks/:id/delete", requireAdmin, async (req, res) => {
    const client = await pool.connect(); // Menggunakan client untuk transaksi
    
    try {
        await client.query("BEGIN"); // Mulai transaksi
        
        const taskId = req.params.id;

        // LANGKAH 1: Hapus semua entri penyelesaian tugas (task_completions)
        await client.query("DELETE FROM task_completions WHERE task_id = $1", [taskId]); 

        // LANGKAH 2: Hapus tugas utama (tasks)
        await client.query("DELETE FROM tasks WHERE id = $1", [taskId]);
        
        await client.query("COMMIT"); // Selesaikan transaksi
        
        req.flash("success_msg", "Tugas berhasil dihapus secara keseluruhan.");
        res.redirect("/admin/tasks");
    } catch (err) {
        await client.query("ROLLBACK"); // Batalkan jika terjadi error
        console.error("Hapus tugas error:", err.message);
        
        // Peringatan: Error ini mungkin terjadi jika ada Foreign Key lain yang merujuk ke 'tasks' 
        // selain task_completions yang belum kita ketahui.
        req.flash("error_msg", "Gagal menghapus tugas. Data tugas mungkin masih terikat.");
        res.redirect("/admin/tasks");
    } finally {
        client.release(); // Selalu bebaskan client
    }
});

// ============= LIVE STREAM ROUTES =================

// READ: Menampilkan daftar semua livestream + Status Worker PM2
app.get("/admin/livestream", requireAdmin, async (req, res) => {
    // 1. Logika untuk mendapatkan Status Worker PM2
    pm2.connect(async (err) => {
        let workerStatus = 'OFFLINE';
        
        if (!err) {
            // Gunakan Promise untuk menangani pm2.list
            const list = await new Promise((resolve, reject) => pm2.list((e, l) => (e ? reject(e) : resolve(l))));
            pm2.disconnect();
            
            const worker = list.find(app => app.name === 'yt-point-worker');
            if (worker && worker.pm2_env.status === 'online') {
                workerStatus = 'ONLINE';
            }
        }
        
        // 2. Logika Database dan Rendering
        try {
            const streamsRes = await pool.query("SELECT * FROM livestreams ORDER BY created_at DESC");
            res.render("admin/livestream", {
                title: "Kelola Livestream",
                user: req.user,
                streams: streamsRes.rows,
                workerStatus: workerStatus, // <--- Variabel dikirim ke EJS
            });
        } catch (dbErr) {
            console.error("Admin livestream error:", dbErr);
            req.flash("error_msg", "Gagal memuat data livestream.");
            res.redirect("/admin/dashboard");
        }
    });
});

// CREATE (PROCESS): Memproses penambahan livestream baru
// Rute ini akan MENYIMPAN data dan MENGATUR stream terbaru sebagai 'active' di DB.
app.post("/admin/livestream/new", requireAdmin, async (req, res) => {
    const { title, videoId } = req.body;
    try {
        // Mendapatkan Live Chat ID dari YouTube API
        const response = await youtube.videos.list({ part: 'liveStreamingDetails', id: videoId });
        if (!response.data.items[0]?.liveStreamingDetails?.activeLiveChatId) {
            req.flash("error_msg", "Gagal mendapatkan Live Chat ID. Pastikan Video ID valid dan Live Chat aktif.");
            return res.redirect("/admin/livestream");
        }
        const liveChatId = response.data.items[0].liveStreamingDetails.activeLiveChatId;
        
        // Nonaktifkan semua stream lama dan aktifkan yang baru
        await pool.query("UPDATE livestreams SET status = 'finished' WHERE status = 'active'");
        await pool.query(
            "INSERT INTO livestreams (title, youtube_video_id, live_chat_id, status) VALUES ($1, $2, $3, 'active')",
            [title, videoId, liveChatId]
        );

        // Setelah data disimpan, worker dapat di-START dari dashboard
        req.flash("success_msg", "Livestream berhasil disimpan dan diatur sebagai AKTIF. Silakan START Worker Poin.");
        res.redirect("/admin/livestream");
    } catch (err) {
        console.error("Gagal menambah livestream:", err);
        req.flash("error_msg", "Terjadi kesalahan saat menambah livestream.");
        res.redirect("/admin/livestream");
    }
});

// Rute CRUD lainnya (CREATE FORM, UPDATE, DELETE) tetap sama.
// ...

// ============= WORKER CONTROL API ROUTES =================

// Endpoint untuk Mendapatkan Status Worker (AJAX)
app.get('/admin/worker/status', requireAdmin, (req, res) => {
    pm2.connect(function(err) {
        let workerStatus = 'OFFLINE';
        if (err) return res.json({ status: 'OFFLINE' });
        
        pm2.list((err, list) => {
            pm2.disconnect();
            const worker = list.find(app => app.name === 'yt-point-worker');
            if (worker && worker.pm2_env.status === 'online') {
                workerStatus = 'ONLINE';
            }
            res.json({ status: workerStatus });
        });
    });
});

// Endpoint untuk Memulai Worker
app.post('/admin/worker/start', requireAdmin, (req, res) => {
    pm2.connect(function(err) {
        if (err) return res.status(500).json({ success: false, message: 'Koneksi PM2 gagal.' });
        
        pm2.start({
            script: 'youtube-worker.js',
            name: 'yt-point-worker',
            exec_mode: 'fork'
        }, (err, apps) => {
            pm2.disconnect();
            if (err) return res.json({ success: false, message: 'Gagal memulai worker: ' + err.message });
            res.json({ success: true, message: 'Worker Poin berhasil dimulai!' });
        });
    });
});

// Endpoint untuk Menghentikan Worker
app.post('/admin/worker/stop', requireAdmin, (req, res) => {
    pm2.connect(function(err) {
        if (err) return res.status(500).json({ success: false, message: 'Koneksi PM2 gagal.' });
        
        pm2.stop('yt-point-worker', (err, apps) => {
            pm2.disconnect();
            if (err && !err.message.includes('process name not found')) {
                console.warn('Attempted to stop worker, potential issue:', err.message);
            }
            res.json({ success: true, message: 'Worker Poin berhasil dihentikan.' });
        });
    });
});

// ================= ROUTES: ADMIN RAFFLES (MANUAL WINNER SELECTION) =================

// ROUTE 1: GET /admin/raffles (READ: Menampilkan daftar semua raffles + Peserta + Pemenang)
app.get("/admin/raffles", requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                r.id, r.title, r.reward, r.status, r.draw_date, r.created_at,
                r.winner_username, -- Ambil username pemenang untuk ditampilkan
                COUNT(re.id) AS total_entries 
            FROM raffles r
            LEFT JOIN raffle_entries re ON r.id = re.raffle_id
            GROUP BY r.id, r.title, r.reward, r.status, r.draw_date, r.created_at, r.winner_username
            ORDER BY r.created_at DESC
        `;
        const rafflesRes = await pool.query(query);
        
        res.render("admin/raffles", {
            title: "Kelola Raffles",
            user: req.user,
            raffles: rafflesRes.rows,
        });
    } catch (err) {
        console.error("Admin raffles error:", err);
        req.flash("error_msg", "Gagal memuat daftar raffle.");
        res.render("admin/raffles", {
            title: "Kelola Raffles",
            user: req.user,
            raffles: [],
        });
    }
});

// ROUTE 2: GET /admin/raffles/:id/select-winner (Menampilkan halaman form pemilihan pemenang)
app.get("/admin/raffles/:id/select-winner", requireAdmin, async (req, res) => {
    const raffleId = req.params.id;
    try {
        const raffleRes = await pool.query("SELECT id, title, status FROM raffles WHERE id = $1", [raffleId]);
        if (raffleRes.rows.length === 0) {
            req.flash("error_msg", "Raffle tidak ditemukan.");
            return res.redirect("/admin/raffles");
        }
        const raffle = raffleRes.rows[0];

        if (raffle.status === 'drawn') {
            req.flash("error_msg", "Raffle ini sudah diundi/ditentukan pemenangnya.");
            return res.redirect("/admin/raffles");
        }

        const entriesQuery = `
            SELECT 
                u.id AS user_id, u.username, u.email, re.entry_time
            FROM raffle_entries re
            JOIN users u ON re.user_id = u.id
            WHERE re.raffle_id = $1
            ORDER BY u.username ASC
        `;
        const entriesRes = await pool.query(entriesQuery, [raffleId]);

        res.render("admin/select-winner", { // Membutuhkan file EJS baru: views/admin/select-winner.ejs
            title: `Pilih Pemenang: ${raffle.title}`,
            user: req.user,
            raffleId: raffleId,
            raffleTitle: raffle.title,
            entries: entriesRes.rows,
        });
    } catch (err) {
        console.error("Select winner page error:", err);
        req.flash("error_msg", "Gagal memuat halaman pemilihan pemenang.");
        res.redirect("/admin/raffles");
    }
});

// ROUTE BARU: GET /admin/raffles/:id/edit (Menampilkan form edit)
app.get("/admin/raffles/:id/edit", requireAdmin, async (req, res) => {
    const raffleId = req.params.id;
    try {
        // Ambil data raffle dari database
        const raffleRes = await pool.query("SELECT * FROM raffles WHERE id = $1", [raffleId]);

        if (raffleRes.rows.length === 0) {
            req.flash("error_msg", "Raffle tidak ditemukan.");
            return res.redirect("/admin/raffles");
        }

        // Render form edit dengan data raffle yang ada
        res.render("admin/edit-raffle", {
            title: "Edit Raffle",
            user: req.user,
            raffle: raffleRes.rows[0], // Mengirim data raffle
        });
    } catch (err) {
        console.error("Get edit raffle error:", err);
        req.flash("error_msg", "Gagal memuat data raffle untuk diedit.");
        res.redirect("/admin/raffles");
    }
});

// ROUTE EXISTING: POST /admin/raffles/:id/edit (Memproses submit form)
app.post("/admin/raffles/:id/edit", requireAdmin, async (req, res) => {
});

// ROUTE 3: POST /admin/raffles/:id/set-winner (Menyimpan pemenang yang dipilih secara manual)
app.post("/admin/raffles/:id/set-winner", requireAdmin, async (req, res) => {
    const raffleId = req.params.id;
    const { winner_id } = req.body;

    if (!winner_id) {
        req.flash("error_msg", "ID pemenang harus dipilih.");
        return res.redirect(`/admin/raffles/${raffleId}/select-winner`);
    }

    try {
        // Ambil username pemenang
        const winnerUserRes = await pool.query("SELECT username FROM users WHERE id = $1", [winner_id]);
        if (winnerUserRes.rows.length === 0) {
            req.flash("error_msg", "User ID pemenang tidak valid.");
            return res.redirect(`/admin/raffles/${raffleId}/select-winner`);
        }
        const winnerUsername = winnerUserRes.rows[0].username;

        // Update status raffle di database (status=drawn, simpan winner_id dan username)
        await pool.query(
            "UPDATE raffles SET status = 'drawn', winner_id = $1, winner_username = $2, draw_date = NOW() WHERE id = $3",
            [winner_id, winnerUsername, raffleId]
        );

        req.flash("success_msg", `Pemenang Raffle berhasil ditentukan secara manual: ${winnerUsername}`);
        res.redirect("/admin/raffles");
    } catch (err) {
        console.error("Set winner error:", err);
        req.flash("error_msg", "Gagal menetapkan pemenang.");
        res.redirect("/admin/raffles");
    }
});

// ROUTE 4: POST /admin/raffles/new (CREATE: Tambah raffle)
app.post("/admin/raffles/new", requireAdmin, async (req, res) => {
    const { title, reward, status, draw_date } = req.body;
    try {
        await pool.query(
            "INSERT INTO raffles (title, reward, status, draw_date) VALUES ($1,$2,$3,$4)",
            [title, reward, status, draw_date]
        );
        
        // ================= BLOK NOTIFIKASI BARU =================
        // io.emit mengirim notifikasi ke semua user yang sedang online
        io.emit('new_raffle', { 
            title: title, 
            message: `🎉 RAFFLE BARU! ${title} telah dimulai! Hadiah: ${reward}. Tukar poin Anda!` 
        });
        // =========================================================
        
        req.flash("success_msg", "Raffle berhasil ditambahkan.");
        res.redirect("/admin/raffles");
    } catch (err) {
        console.error("Tambah raffle error:", err);
        req.flash("error_msg", "Gagal menambahkan raffle.");
        res.redirect("/admin/raffles");
    }
});

// ROUTE 5: POST /admin/raffles/:id/edit (UPDATE: Edit raffle)
app.post("/admin/raffles/:id/edit", requireAdmin, async (req, res) => {
    const { title, reward, status, draw_date } = req.body;
    try {
        await pool.query(
            "UPDATE raffles SET title=$1, reward=$2, status=$3, draw_date=$4 WHERE id=$5",
            [title, reward, status, draw_date, req.params.id]
        );
        req.flash("success_msg", "Raffle berhasil diperbarui.");
        res.redirect("/admin/raffles");
    } catch (err) {
        console.error("Edit raffle error:", err);
        req.flash("error_msg", "Gagal memperbarui raffle.");
        res.redirect("/admin/raffles");
    }
});

// ROUTE 6: POST /admin/raffles/:id/delete (DELETE: Hapus raffle)
app.post("/admin/raffles/:id/delete", requireAdmin, async (req, res) => {
    try {
        await pool.query("DELETE FROM raffles WHERE id=$1", [req.params.id]);
        req.flash("success_msg", "Raffle berhasil dihapus.");
        res.redirect("/admin/raffles");
    } catch (err) {
        console.error("Hapus raffle error:", err);
        req.flash("error_msg", "Gagal menghapus raffle.");
        res.redirect("/admin/raffles");
    }
});

// ROUTE 7: GET /admin/raffles/:id/entries (Menampilkan Daftar Peserta)
app.get("/admin/raffles/:id/entries", requireAdmin, async (req, res) => {
    const raffleId = req.params.id;
    try {
        const entriesQuery = `
            SELECT 
                u.username, u.email, re.entry_time
            FROM raffle_entries re
            JOIN users u ON re.user_id = u.id
            WHERE re.raffle_id = $1
            ORDER BY re.entry_time ASC
        `;
        const entriesRes = await pool.query(entriesQuery, [raffleId]);

        const raffleRes = await pool.query("SELECT title FROM raffles WHERE id = $1", [raffleId]);
        const raffleTitle = raffleRes.rows.length > 0 ? raffleRes.rows[0].title : "Raffle Tidak Ditemukan";

        res.render("admin/raffle-entries", {
            title: `Peserta Raffle: ${raffleTitle}`,
            user: req.user,
            entries: entriesRes.rows,
            raffleTitle: raffleTitle
        });
    } catch (err) {
        console.error("Raffle entries error:", err);
        req.flash("error_msg", "Gagal memuat daftar peserta.");
        res.redirect("/admin/raffles");
    }
});

// ================ ROUTES ADMIN CLAIM CODE ====================

// GET: Menampilkan halaman Kelola Claim Code (READ)
app.get("/admin/claim-code", requireAdmin, async (req, res) => {
    try {
        // Query ini sekarang mengambil semua kolom baru dan menghitung total klaim (redeemed_count)
        const query = `
            SELECT 
                cc.id,
                cc.code,
                cc.reward AS points,
                cc.status,
                cc.created_at,
                cc.expiry_date, 
                cc.max_claims,
                -- Menghitung jumlah klaim berdasarkan tabel claim_code_redemptions
                COALESCE(COUNT(ccr.id), 0) AS redeemed_count
            FROM claim_codes cc 
            LEFT JOIN claim_code_redemptions ccr ON cc.id = ccr.code_id
            GROUP BY cc.id, cc.code, cc.reward, cc.status, cc.created_at, cc.expiry_date, cc.max_claims
            ORDER BY cc.created_at DESC
        `;
        const codesRes = await pool.query(query);

        res.render("admin/claim-code", {
            title: "Kelola Claim Code",
            user: req.user,
            codes: codesRes.rows,
        });
    } catch (err) {
        console.error("Admin claim-code error:", err);
        req.flash("error_msg", "Gagal memuat daftar kode.");
        res.render("admin/claim-code", { 
            title: "Kelola Claim Code", 
            user: req.user, 
            codes: [] 
        });
    }
});

// POST: Membuat Claim Code baru (CREATE)
app.post("/admin/claim-code/new", requireAdmin, async (req, res) => {
    // Ambil semua field baru dari form
    const { code, expiry_date, max_claims } = req.body; 
    const points = parseInt(req.body.points);
    
    // Validasi dan konversi data baru
    const maxClaimsInt = parseInt(max_claims) || 0;
    // Gunakan null jika tanggal kosong, jika tidak, konversi ke objek Date
    const expiryDateObj = expiry_date ? new Date(expiry_date) : null; 

    if (!code || !points || isNaN(points)) {
        req.flash("error_msg", "Kode dan Poin harus diisi dengan benar.");
        return res.redirect("/admin/claim-code");
    }

    try {
        await pool.query(
            // UPDATE: Tambahkan expiry_date dan max_claims ke query INSERT
            "INSERT INTO claim_codes (code, reward, expiry_date, max_claims) VALUES ($1, $2, $3, $4)",
            [code.toUpperCase(), points, expiryDateObj, maxClaimsInt] 
        );
        req.flash("success_msg", "Claim code baru berhasil ditambahkan.");
        res.redirect("/admin/claim-code");
    } catch (err) {
        console.error("!!! GAGAL: Terjadi error saat query database:", err); 
        
        if (err.code === '23505') {
            req.flash("error_msg", `Gagal: Kode '${code.toUpperCase()}' sudah ada.`);
        } else {
            req.flash("error_msg", "Gagal menambahkan claim code. Cek konsol server untuk detail.");
        }
        res.redirect("/admin/claim-code");
    }
});

// POST: Menghapus Claim Code (DELETE)
app.post("/admin/claim-code/:id/delete", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        // Hapus riwayat pemakaiannya (penting untuk integrity)
        await client.query("DELETE FROM claim_code_redemptions WHERE code_id = $1", [id]);
        // Hapus kode utamanya
        await client.query("DELETE FROM claim_codes WHERE id = $1", [id]);
        await client.query("COMMIT");

        req.flash("success_msg", "Claim code berhasil dihapus.");
        res.redirect("/admin/claim-code");
    } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error menghapus claim code:", err);
        req.flash("error_msg", "Gagal menghapus claim code.");
        res.redirect("/admin/claim-code");
    } finally {
        client.release();
    }
});

//VERIF MANUAL & OTOMATIS TASKS ROUTES//
// POST: Menyetujui pengajuan tugas (Approve)
app.post("/admin/verifications/:submissionId/approve", requireAdmin, async (req, res) => {
    const submissionId = req.params.submissionId;
    const client = await pool.connect();
    
    try {
        await client.query("BEGIN");
        
        // 1. Ambil detail pengajuan untuk mendapatkan user_id dan reward
        const submissionRes = await client.query(`
            SELECT 
                tc.user_id, 
                t.reward 
            FROM task_completions tc
            JOIN tasks t ON tc.task_id = t.id
            WHERE tc.id = $1 AND tc.status = 'pending'
        `, [submissionId]);

        if (submissionRes.rows.length === 0) {
            await client.query("COMMIT");
            req.flash("error_msg", "Pengajuan tidak ditemukan atau sudah diverifikasi.");
            return res.redirect("/admin/verifications");
        }
        
        const { user_id, reward } = submissionRes.rows[0];

        // 2. Beri Poin kepada Pengguna
        await client.query("UPDATE users SET points = points + $1 WHERE id = $2", [reward, user_id]);
        
        // 3. Tandai pengajuan sebagai 'approved'
        await client.query("UPDATE task_completions SET status = 'approved' WHERE id = $1", [submissionId]);
        
        await client.query("COMMIT");

        req.flash("success_msg", `Tugas berhasil disetujui! +${reward} Poin diberikan.`);
        res.redirect("/admin/verifications");
    } catch (err) {
        await client.query("ROLLBACK");
        console.error("Approve task error:", err);
        req.flash("error_msg", "Gagal menyetujui tugas.");
        res.redirect("/admin/verifications");
    } finally {
        client.release();
    }
});

// POST: Menolak pengajuan tugas (Reject)
app.post("/admin/verifications/:submissionId/reject", requireAdmin, async (req, res) => {
    const submissionId = req.params.submissionId;
    try {
        // Tandai pengajuan sebagai 'rejected'
        await pool.query("UPDATE task_completions SET status = 'rejected' WHERE id = $1", [submissionId]);
        
        req.flash("warning_msg", "Pengajuan tugas berhasil ditolak.");
        res.redirect("/admin/verifications");
    } catch (err) {
        console.error("Reject task error:", err);
        req.flash("error_msg", "Gagal menolak tugas.");
        res.redirect("/admin/verifications");
    }
});

// ROUTE PUBLIK: Menangani Pengalihan Tugas Otomatis (Link Click)
app.get("/task/verify/:taskId", requireLogin, async (req, res) => {
    const taskId = req.params.taskId;
    const userId = req.user.id;
    
    if (!userId) {
        req.flash("error_msg", "Anda harus login untuk memverifikasi tugas.");
        return res.redirect("/login");
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        
        // 1. Cek Tugas (Hanya yang bertipe 'link_click' dan 'active')
        const taskRes = await client.query(
            "SELECT reward, verification_url FROM tasks WHERE id = $1 AND status = 'active' AND task_type = 'link_click'", 
            [taskId]
        );
        
        if (taskRes.rows.length === 0) {
            req.flash("error_msg", "Tugas tidak aktif, tidak ditemukan, atau memerlukan verifikasi manual.");
            await client.query("COMMIT");
            return res.redirect("/dashboard");
        }
        const task = taskRes.rows[0];

        // 2. Cek apakah User sudah menyelesaikan Tugas
        const completionRes = await client.query(
            "SELECT 1 FROM task_completions WHERE user_id = $1 AND task_id = $2 AND (status = 'completed' OR status = 'approved')",
            [userId, taskId]
        );
        if (completionRes.rows.length > 0) {
            req.flash("warning_msg", "Anda sudah menyelesaikan tugas ini.");
            await client.query("COMMIT");
            return res.redirect(task.verification_url); 
        }

        // 3. LOGIKA PEMBERIAN POIN OTOMATIS
        await client.query("UPDATE users SET points = points + $1 WHERE id = $2", [task.reward, userId]);
        await client.query(
            "INSERT INTO task_completions (user_id, task_id, status) VALUES ($1, $2, 'approved')", // Langsung set status 'approved'
            [userId, taskId]
        );
        
        await client.query("COMMIT");
        
        req.flash("success_msg", `Berhasil! Anda mendapatkan ${task.reward} Poin.`);
        return res.redirect(task.verification_url); 

    } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error verifikasi tugas otomatis:", err);
        req.flash("error_msg", "Terjadi kesalahan saat memproses tugas.");
        return res.redirect("/dashboard");
    } finally {
        client.release();
    }
});

// Kelola Wallet User
app.get("/admin/wallet", requireAdmin, async (req, res) => {
  try {
    const walletsRes = await pool.query(
      `SELECT uw.id, u.username, uw.currency, uw.balance, uw.created_at
       FROM users_wallet uw
       JOIN users u ON uw.user_id = u.id
       ORDER BY uw.created_at DESC`
    );
    res.render("admin/wallet", {
      title: "Kelola Wallet",
      user: req.user,
      wallets: walletsRes.rows,
    });
  } catch (err) {
    console.error("Admin wallet error:", err);
    res.render("admin/wallet", { title: "Kelola Wallet", user: req.user, wallets: [] });
  }
});

// Term Of Reffrence//

app.get("/terms", (req, res) => {
    res.render("terms", {
        title: "Terms of Service",
        // Asumsi header/footer Anda memerlukan variabel user
        user: req.user || { username: 'Guest' } 
    });
});

app.get("/privacy-policy", (req, res) => {
    res.render("privacy-policy", { 
        title: "Privacy Policy",
        user: req.user || { username: 'Guest' }
    });
});

// ================= START SERVER =================
// Menghidupkan server gabungan (HTTP + WebSocket)
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`🚀 Server berjalan di Port ${PORT}`));
