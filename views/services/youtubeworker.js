const { google } = require('googleapis');
const pool = require('../db.js'); // Pastikan path ke file koneksi DB Anda benar

const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY; // Pastikan ada di file .env
const youtube = google.youtube({ version: 'v3', auth: YOUTUBE_API_KEY });

let nextPageToken = null; // Untuk mengambil halaman chat selanjutnya

async function checkLiveChatAndAwardPoints() {
    console.log('Worker: Mengecek pesan live chat...');
    
    const streamRes = await pool.query("SELECT id, live_chat_id FROM livestreams WHERE status = 'active' LIMIT 1");
    if (streamRes.rows.length === 0) {
        return; // Tidak ada stream aktif, berhenti.
    }
    const { id: streamId, live_chat_id: liveChatId } = streamRes.rows[0];

    try {
        const chatRes = await youtube.liveChatMessages.list({
            liveChatId: liveChatId,
            part: 'snippet,authorDetails',
            pageToken: nextPageToken
        });

        const newMessages = chatRes.data.items;
        nextPageToken = chatRes.data.nextPageToken; // Simpan token untuk panggilan berikutnya

        for (const message of newMessages) {
            const messageTime = new Date(message.snippet.publishedAt);
            const authorChannelId = message.authorDetails.channelId;
            
            const userRes = await pool.query(
                "SELECT id, points, last_point_awarded_at FROM users WHERE youtube_channel_id = $1", 
                [authorChannelId]
            );

            if (userRes.rows.length > 0) {
                const user = userRes.rows[0];
                const TEN_MINUTES_IN_MS = 10 * 60 * 1000;
                const lastAwardedTime = user.last_point_awarded_at ? new Date(user.last_point_awarded_at) : null;
                
                if (!lastAwardedTime || (messageTime.getTime() - lastAwardedTime.getTime() > TEN_MINUTES_IN_MS)) {
                    const newPoints = user.points + 10;
                    await pool.query(
                        "UPDATE users SET points = $1, last_point_awarded_at = $2 WHERE id = $3",
                        [newPoints, messageTime, user.id]
                    );
                    console.log(`+10 poin untuk user ID ${user.id}!`);
                }
            }
        }
    } catch (err) {
        if (err.message.includes('The live chat is no longer live')) {
          console.log(`Worker: Live chat untuk stream ${streamId} telah berakhir.`);
          await pool.query("UPDATE livestreams SET status = 'finished' WHERE id = $1", [streamId]);
          nextPageToken = null; // Reset token
        } else {
          console.error('Worker Error:', err.message);
        }
    }
}

function startWorker() {
    // Jalankan worker setiap 2 menit (120000 ms) untuk menghemat kuota
    console.log('YouTube Point Worker dimulai...');
    setInterval(checkLiveChatAndAwardPoints, 120000);
}

module.exports = { startWorker };