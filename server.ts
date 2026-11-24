import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { createApp } from './server/app.ts';
import { loadConfig } from './server/config.ts';
import { initDatabase } from './server/db.ts';

dotenv.config();

async function startServer() {
  const config = loadConfig();
  const db = initDatabase(config.dbPath);
  const app = createApp({ db, config });

  if (config.nodeEnv !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      const indexPath = path.resolve(distDir, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(404).send('Build output missing. Run npm run build.');
      }
    });
  }

  app.listen(config.port, '0.0.0.0', () => {
    console.log(`9HR India server listening on http://0.0.0.0:${config.port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start 9HR India server:', err);
  process.exit(1);
});
