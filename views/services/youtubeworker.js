const { google } = require('googleapis');
// Asumsi db.js sudah meng-export pool koneksi
const pool = require('./db.js'); 
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY; 
const youtube = google.youtube({ version: 'v3', auth: YOUTUBE_API_KEY });

// next page token harus disimpan di scope yang bisa diakses oleh interval
let nextPageToken = null; 
// Interval polling disetel ke 10 detik atau 15 detik agar tidak melampaui quota YouTube API
const POLLING_INTERVAL_MS = 15000; 

async function checkLiveChatAndAwardPoints() {
    console.log(`[${new Date().toLocaleTimeString()}] Worker: Mengecek pesan live chat...`);
    
    // 1. Ambil Stream Aktif dari Database
    // Asumsi: Table livestreams memiliki kolom 'live_chat_id' dan 'video_id'
    const streamRes = await pool.query("SELECT id, live_chat_id, start_time FROM livestreams WHERE status = 'active' LIMIT 1");
    
    if (streamRes.rows.length === 0) {
        console.log('Worker: Tidak ada stream aktif, menunggu...');
        return; 
    }
    
    const { id: streamId, live_chat_id: liveChatId } = streamRes.rows[0];

    try {
        // 2. Panggil YouTube Live Chat API
        const chatRes = await youtube.liveChatMessages.list({
            liveChatId: liveChatId,
            part: 'snippet,authorDetails',
            pageToken: nextPageToken,
            // Perhatikan bahwa interval API harus sesuai dengan interval panggilan di startWorker()
        });

        const newMessages = chatRes.data.items || [];
        nextPageToken = chatRes.data.nextPageToken;

        for (const message of newMessages) {
            const messageTime = new Date(message.snippet.publishedAt);
            const authorChannelId = message.authorDetails.channelId;
            const messageText = message.snippet.displayMessage;
            
            // 3. Cari User yang Menautkan Akun
            const userRes = await pool.query(
                "SELECT id, points, first_chat_claimed, last_point_awarded_at FROM users WHERE youtube_channel_id = $1", 
                [authorChannelId]
            );

            if (userRes.rows.length > 0) {
                const user = userRes.rows[0];
                let pointsToAdd = 0;
                let isFirstChat = false;
                
                // === LOGIKA POIN PERTAMA (10 Poin) ===
                if (!user.first_chat_claimed) {
                    pointsToAdd += 10; // Poin untuk chat pertama
                    isFirstChat = true;
                    console.log(`[POIN PERTAMA] +10 untuk user ID ${user.id} (${authorChannelId})`);
                }

                // === LOGIKA POIN BERKALA (10 Menit) ===
                const TEN_MINUTES_IN_MS = 10 * 60 * 1000;
                const lastAwardedTime = user.last_point_awarded_at ? new Date(user.last_point_awarded_at) : null;
                
                // Beri poin jika sudah lebih dari 10 menit sejak poin terakhir diberikan
                if (lastAwardedTime && (messageTime.getTime() - lastAwardedTime.getTime() >= TEN_MINUTES_IN_MS)) {
                    pointsToAdd += 10; // Poin bonus waktu
                    console.log(`[POIN BONUS] +10 untuk user ID ${user.id} (${authorChannelId})`);
                }
                
                // 4. Update Database jika poin diberikan
                if (pointsToAdd > 0) {
                    const newPoints = user.points + pointsToAdd;
                    
                    // Gunakan transaksi untuk memastikan atomicity
                    await pool.query('BEGIN');
                    
                    const updateQuery = `
                        UPDATE users SET 
                            points = $1, 
                            last_point_awarded_at = $2,
                            ${isFirstChat ? 'first_chat_claimed = TRUE,' : ''}
                            updated_at = NOW()
                        WHERE id = $3
                    `;
                    
                    await pool.query(updateQuery, [newPoints, messageTime, user.id]);
                    await pool.query('COMMIT');
                    
                    console.log(`Worker: Total Poin ditambahkan: ${pointsToAdd} untuk User: ${user.id}. Total baru: ${newPoints}`);
                }
            }
        }
        
        // Catatan: Anda perlu memastikan status 'active' di livestreams disetel ke 'finished'
        // saat live chat berakhir untuk menghindari loop API yang tidak perlu.

    } catch (err) {
        if (err.message.includes('The live chat is no longer live')) {
          console.log(`Worker: Live chat untuk stream ${streamId} telah berakhir. Menghentikan worker.`);
          // *** PENTING: Anda perlu menghentikan proses PM2 dari luar! ***
          // Worker ini harus dihentikan secara manual (pm2 stop) atau dihentikan dari dashboard admin
          
          await pool.query("UPDATE livestreams SET status = 'finished' WHERE id = $1", [streamId]);
          nextPageToken = null; // Reset token
        } else if (err.message.includes('No live chat for the specified broadcast')) {
            console.error('Worker Error: Broadcast sudah berakhir atau Live Chat ID salah.');
            // Update status menjadi 'finished' atau 'error'
            await pool.query("UPDATE livestreams SET status = 'finished' WHERE id = $1", [streamId]);
        } else {
            // Error API lainnya (quota limit, dll.)
            console.error('Worker Error API:', err.message);
        }
    }
}

function startWorker() {
    console.log('YouTube Point Worker dimulai. Polling setiap 15 detik.');
    // Mulai worker setiap 15 detik (di bawah batas yang disarankan YouTube untuk live chat API)
    setInterval(checkLiveChatAndAwardPoints, POLLING_INTERVAL_MS);
}

module.exports = { checkLiveChatAndAwardPoints, startWorker };