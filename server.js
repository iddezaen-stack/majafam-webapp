require("dotenv").config();
const express = require("express");
const session = require("express-session");
const flash = require("connect-flash");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const path = require("path");
const pm2 = require("pm2");
const app = express();
const { google } = require('googleapis');
const youtube = google.youtube({ version: 'v3', auth: process.env.YOUTUBE_API_KEY });

// ================= DATABASE =================
const pool = new Pool({
  host: "localhost",
  port: 5432,
  user: "postgres",
  password: process.env.DB_PASSWORD,
  database: "majafam_web",
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

// MIDDLEWARE TIP
app.use((req, res, next) => {
    res.locals.user = req.user || null;
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

// ================= ROUTES: TASKS =================
app.get("/tasks", ensureAuthenticated, async (req, res) => {
  try {
    const { wallets, selectedWallet } = await loadWallets(req);
    const tasksRes = await pool.query("SELECT * FROM tasks WHERE status='active' ORDER BY created_at DESC");
    res.render("tasks", { 
      title: "Tugas", 
      user: req.user, 
      wallets, 
      selectedWallet,
      tasks: tasksRes.rows 
    });
  } catch (err) {
    console.error(err);
    res.render("tasks", { 
      title: "Tugas", 
      user: req.user, 
      wallets: [], 
      selectedWallet: { currency: "IDR", balance: 0 },
      tasks: [] 
    });
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

// ROUTES : TUKAR-POINT ===============================//
// Menampilkan halaman tukar poin
app.get("/tukar-point", ensureAuthenticated, async (req, res) => {
    try {
        // Ambil riwayat poin untuk user yang sedang login
        const historyRes = await pool.query(
            "SELECT * FROM point_history WHERE user_id = $1 ORDER BY created_at DESC",
            [req.user.id]
        );

        res.render("tukar-point", {
            title: "Tukar Poin",
            user: req.user,
            history: historyRes.rows // Kirim data riwayat ke EJS
        });
    } catch (err) {
        console.error("Error loading tukar-point page:", err);
        req.flash("error_msg", "Gagal memuat halaman.");
        res.redirect("/dashboard");
    }
});

// Memproses form penukaran poin ke tiket raffle
app.post("/tukar-point", ensureAuthenticated, async (req, res) => {
    const { jumlah } = req.body;
    const userId = req.user.id;
    const pointsToExchange = parseInt(jumlah);

    // --- Validasi Input ---
    if (!pointsToExchange || pointsToExchange < 100 || pointsToExchange % 100 !== 0) {
        req.flash("error_msg", "Jumlah poin harus dalam kelipatan 100.");
        return res.redirect("/tukar-point");
    }

    const client = await pool.connect();
    try {
        // Cek apakah ada raffle yang aktif
        const raffleRes = await client.query("SELECT id FROM raffles WHERE status = 'active' ORDER BY created_at DESC LIMIT 1");
        if (raffleRes.rows.length === 0) {
            req.flash("error_msg", "Saat ini tidak ada raffle yang aktif untuk diikuti.");
            return res.redirect("/tukar-point");
        }
        const raffleId = raffleRes.rows[0].id;

        // Cek saldo poin pengguna
        const userRes = await client.query("SELECT points FROM users WHERE id = $1", [userId]);
        const userPoints = userRes.rows[0].points;
        
        if (userPoints < pointsToExchange) {
            req.flash("error_msg", "Poin Anda tidak cukup untuk melakukan penukaran.");
            return res.redirect("/tukar-point");
        }

        // --- Mulai Transaksi Database ---
        await client.query("BEGIN");

        // 1. Kurangi poin user
        await client.query("UPDATE users SET points = points - $1 WHERE id = $2", [pointsToExchange, userId]);
        
        // 2. Catat di riwayat poin
        await client.query(
            "INSERT INTO point_history (user_id, reward, points, status) VALUES ($1, $2, $3, $4)",
            [userId, `Tukar ${pointsToExchange} poin ke tiket raffle`, -pointsToExchange, "success"]
        );

        // 3. Buat tiket raffle sebanyak jumlah poin / 100
        const ticketCount = pointsToExchange / 100;
        for (let i = 0; i < ticketCount; i++) {
            await client.query(
                "INSERT INTO raffle_entries (raffle_id, user_id) VALUES ($1, $2)",
                [raffleId, userId]
            );
        }

        await client.query("COMMIT");
        // --- Transaksi Selesai ---
        
        req.flash("success_msg", `Berhasil menukar ${pointsToExchange} poin dengan ${ticketCount} tiket raffle!`);
        res.redirect("/tukar-point");

    } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error exchanging points:", err);
        req.flash("error_msg", "Terjadi kesalahan saat menukar poin.");
        res.redirect("/tukar-point");
    } finally {
        client.release();
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
// ================= ROUTES RIWAYAT ===============

app.get("/history", ensureAuthenticated, async (req, res) => {
  try {
    const historyRes = await pool.query(
      "SELECT * FROM history WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    
    // ambil wallets agar header tidak error
    const walletRes = await pool.query("SELECT * FROM users_wallet WHERE user_id=$1", [req.user.id]);
    const wallets = walletRes.rows;
    const selectedWallet = wallets[0] || { currency: "IDR", balance: 0 };

    res.render("history", {
      title: "Riwayat Aktivitas",
      user: req.user,
      history: historyRes.rows,
      wallets: [], // biar header/wallet-overview tidak error
      selectedWallet: { currency: "IDR", balance: 0 }
    });
  } catch (err) {
    console.error("History error:", err);
    res.render("history", {
      title: "Riwayat Aktivitas",
      user: req.user,
      history: [],
      wallets: [],
      selectedWallet: { currency: "IDR", balance: 0 }
    });
  }
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

// redirect /admin -> /admin/dashboard
app.get("/admin", requireAdmin, (req, res) => {
  res.redirect("/admin/dashboard");
});

// Dashboard
app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const totalUsers = await pool.query("SELECT COUNT(*) FROM users");
    const activeTasks = await pool.query("SELECT COUNT(*) FROM tasks WHERE status='active'");
    const activeRaffles = await pool.query("SELECT COUNT(*) FROM raffles WHERE status='active'");
    const totalWallets = await pool.query("SELECT COUNT(*) FROM users_wallet");

    let recentActivity = { rows: [] };
    try {
      recentActivity = await pool.query(
        "SELECT description, created_at FROM activity_log ORDER BY created_at DESC LIMIT 5"
      );
    } catch (err) {
      console.warn("activity_log table not found, skip recentActivity");
    }

    res.render("admin/dashboard", {
      title: "Admin Dashboard",
      user: req.user,
      stats: {
        totalUsers: totalUsers.rows[0].count,
        activeTasks: activeTasks.rows[0].count,
        activeRaffles: activeRaffles.rows[0].count,
        totalWallets: totalWallets.rows[0].count,
      },
      recentActivity: recentActivity.rows,
    });
  } catch (err) {
    console.error("Admin dashboard error:", err);
    res.render("admin/dashboard", {
      title: "Admin Dashboard",
      user: req.user,
      stats: { totalUsers: 0, activeTasks: 0, activeRaffles: 0, totalWallets: 0 },
      recentActivity: [],
    });
  }
});

// ================= ROUTES: ADMIN TASKS =================

// Daftar tugas
app.get("/admin/tasks", requireAdmin, async (req, res) => {
  try {
    const tasksRes = await pool.query("SELECT * FROM tasks ORDER BY created_at DESC");
    res.render("admin/tasks", {
      title: "Kelola Tugas",
      user: req.user,
      tasks: tasksRes.rows
    });
  } catch (err) {
    console.error("Admin tasks error:", err);
    res.render("admin/tasks", { title: "Kelola Tugas", user: req.user, tasks: [] });
  }
});

// Form tambah tugas
app.get("/admin/tasks/new", requireAdmin, (req, res) => {
  res.render("admin/tasks-form", {
    title: "Tambah Tugas",
    user: req.user,
    task: null // kosong karena tambah baru
  });
});

// Proses tambah tugas
app.post("/admin/tasks/new", requireAdmin, async (req, res) => {
  const { title, description, reward, status } = req.body;
  try {
    await pool.query(
      "INSERT INTO tasks (title, description, reward, status) VALUES ($1,$2,$3,$4)",
      [title, description, reward, status]
    );
    req.flash("success_msg", "Tugas berhasil ditambahkan.");
    res.redirect("/admin/tasks");
  } catch (err) {
    console.error("Tambah tugas error:", err);
    req.flash("error_msg", "Gagal menambahkan tugas.");
    res.redirect("/admin/tasks");
  }
});

// Form edit tugas
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
    console.error("Edit tugas error:", err);
    req.flash("error_msg", "Gagal memuat form edit tugas.");
    res.redirect("/admin/tasks");
  }
});

// Proses edit tugas
app.post("/admin/tasks/:id/edit", requireAdmin, async (req, res) => {
  const { title, description, reward, status } = req.body;
  try {
    await pool.query(
      "UPDATE tasks SET title=$1, description=$2, reward=$3, status=$4 WHERE id=$5",
      [title, description, reward, status, req.params.id]
    );
    req.flash("success_msg", "Tugas berhasil diperbarui.");
    res.redirect("/admin/tasks");
  } catch (err) {
    console.error("Update tugas error:", err);
    req.flash("error_msg", "Gagal memperbarui tugas.");
    res.redirect("/admin/tasks");
  }
});

// Hapus tugas
app.post("/admin/tasks/:id/delete", requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
    req.flash("success_msg", "Tugas berhasil dihapus.");
    res.redirect("/admin/tasks");
  } catch (err) {
    console.error("Hapus tugas error:", err);
    req.flash("error_msg", "Gagal menghapus tugas.");
    res.redirect("/admin/tasks");
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

// ================= ROUTES: ADMIN RAFFLES =================

// READ: Menampilkan daftar semua raffles + Jumlah Peserta
app.get("/admin/raffles", requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                r.id, r.title, r.reward, r.status, r.draw_date, r.created_at,
                COUNT(re.id) AS total_entries  -- Menghitung jumlah peserta
            FROM raffles r
            LEFT JOIN raffle_entries re ON r.id = re.raffle_id
            GROUP BY r.id, r.title, r.reward, r.status, r.draw_date, r.created_at
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
        // Tetap render halaman meskipun ada error database
        res.render("admin/raffles", {
            title: "Kelola Raffles",
            user: req.user,
            raffles: [],
        });
    }
});

// GET: Menampilkan Daftar Peserta untuk Raffle Tertentu
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


// Tambah raffle (Tidak Ada Perubahan)
app.post("/admin/raffles/new", requireAdmin, async (req, res) => {
    const { title, reward, status, draw_date } = req.body;
    try {
        await pool.query(
            "INSERT INTO raffles (title, reward, status, draw_date) VALUES ($1,$2,$3,$4)",
            [title, reward, status, draw_date]
        );
        req.flash("success_msg", "Raffle berhasil ditambahkan.");
        res.redirect("/admin/raffles");
    } catch (err) {
        console.error("Tambah raffle error:", err);
        req.flash("error_msg", "Gagal menambahkan raffle.");
        res.redirect("/admin/raffles");
    }
});

// Edit raffle (Tidak Ada Perubahan)
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

// Hapus raffle (Tidak Ada Perubahan)
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

// ================ ROUTES ADMIN CLAIM CODE ====================
// GET: Menampilkan halaman Kelola Claim Code
app.get("/admin/claim-code", requireAdmin, async (req, res) => {
  try {
    // Query ini mengambil semua kode dan juga mengecek apakah sudah pernah dipakai.
     const codesRes = await pool.query(`
      SELECT 
        cc.id,
        cc.code,
        cc.reward AS points, -- Ubah nama kolom 'reward' menjadi 'points' saat query
        cc.status,
        cc.created_at,
        EXISTS (SELECT 1 FROM claim_code_redemptions ccr WHERE ccr.code_id = cc.id) as redeemed
      FROM claim_codes cc 
      ORDER BY cc.created_at DESC
    `);

    res.render("admin/claim-code", {
      title: "Kelola Claim Code",
      user: req.user,
      codes: codesRes.rows,
    });
  } catch (err) {
    console.error("Admin claim-code error:", err);
    res.render("admin/claim-code", { 
      title: "Kelola Claim Code", 
      user: req.user, 
      codes: [] 
    });
  }
});

// POST: Membuat Claim Code baru (dengan logging untuk debug)
app.post("/admin/claim-code/new", requireAdmin, async (req, res) => {
  console.log('--- Menerima request untuk menambah claim code ---');
  console.log('Data dari form (req.body):', req.body); // LOG 1: Lihat data mentah dari form

  // Ambil 'points' dari req.body, sesuai dengan nama input di form
  const { code } = req.body;
  const points = parseInt(req.body.points); // LOG 2: Pastikan points adalah angka
  
  console.log(`Data yang diproses: Code = ${code}, Points = ${points}`);

  if (!code || !points || isNaN(points)) {
    console.log('Validasi gagal: Kode atau Poin kosong atau bukan angka.');
    req.flash("error_msg", "Kode dan Poin harus diisi dengan benar.");
    return res.redirect("/admin/claim-code");
  }

  try {
    console.log('Mencoba memasukkan data ke database...');
    await pool.query(
      "INSERT INTO claim_codes (code, reward) VALUES ($1, $2)",
      [code.toUpperCase(), points] 
    );
    console.log('>>> SUKSES: Data berhasil dimasukkan.');
    req.flash("success_msg", "Claim code baru berhasil ditambahkan.");
    res.redirect("/admin/claim-code");
  } catch (err) {
    // LOG 3: Ini adalah bagian paling penting jika terjadi error
    console.error("!!! GAGAL: Terjadi error saat query database:", err); 
    
    if (err.code === '23505') {
        req.flash("error_msg", `Gagal: Kode '${code.toUpperCase()}' sudah ada.`);
    } else {
        req.flash("error_msg", "Gagal menambahkan claim code. Cek konsol server untuk detail.");
    }
    res.redirect("/admin/claim-code");
  }
});

// POST: Menghapus Claim Code
app.post("/admin/claim-code/:id/delete", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Hapus dulu riwayat pemakaiannya (jika ada)
    await client.query("DELETE FROM claim_code_redemptions WHERE code_id = $1", [id]);
    // Baru hapus kode utamanya
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

// VERIFICATION ADMIN TASK //
// --- Rute Admin untuk Verifikasi ---
app.get("/admin/verifications", requireAdmin, async (req, res) => {
    try {
        const submissionsRes = await pool.query(`
            SELECT 
                tc.id, 
                u.username, 
                t.title as task_title, 
                tc.proof_data, 
                tc.completed_at
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
        req.flash("error_msg", "Gagal memuat halaman verifikasi.");
        res.redirect("/admin/dashboard");
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

// ================= START SERVER =================
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 Server berjalan di http://localhost:${PORT}`));