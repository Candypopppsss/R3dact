import app from '../server/server';

export default async function handler(req: any, res: any) {
    try {
        // Ensure Express handles the request
        return app(req, res);
    } catch (error: any) {
        console.error('CRITICAL: Vercel Entry Point Failure:', error);
        res.status(500).json({
            error: 'CRITICAL_BOOT_ERROR',
            message: error.message,
            stack: error.stack
        });
    }
}
