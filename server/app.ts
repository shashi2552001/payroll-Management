import type Database from 'better-sqlite3';
import cookieParser from 'cookie-parser';
import express from 'express';
import type { Transporter } from 'nodemailer';
import type { AppConfig } from './config.ts';
import { createEmailService, type EmailService } from './email.ts';
import { csrfProtection } from './middleware.ts';
import { createAdminRouter } from './routes/admin.ts';
import { createAuthRouter } from './routes/auth.ts';
import { createCandidatePortalRouter } from './routes/candidatePortal.ts';
import { createCandidatesRouter } from './routes/candidates.ts';
import { createHrRouter } from './routes/hr.ts';

export interface AppDependencies {
  db: Database.Database;
  config: AppConfig;
  emailTransport?: Transporter;
  emailService?: EmailService;
}

export function createApp(deps: AppDependencies): express.Express {
  const { db, config } = deps;
  const emailService =
    deps.emailService || createEmailService(db, config, deps.emailTransport);

  const app = express();
  app.set('trust proxy', 1);

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  app.use(cookieParser());
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: '9HR India' });
  });

  app.use('/api', csrfProtection);
  app.use('/api/auth', createAuthRouter(db, config, emailService));
  app.use('/api/admin', createAdminRouter(db, config));
  app.use('/api/hr', createHrRouter(db, config));
  app.use('/api/candidates', createCandidatesRouter(db, config, emailService));
  app.use('/api/candidate-portal', createCandidatePortalRouter(db, config, emailService));

  // Safe error handler (never expose internal stack traces)
  app.use(
    (
      err: Error & { code?: string },
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      if (err.code === 'LIMIT_FILE_SIZE') {
        res.status(413).json({ error: 'Uploaded file exceeds server upload ceiling.' });
        return;
      }
      res.status(500).json({ error: 'An internal processing error occurred.' });
    },
  );

  return app;
}
