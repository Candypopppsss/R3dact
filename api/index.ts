export default async function handler(req: any, res: any) {
    try {
        // Dynamic import to capture errors during initialization/boot
        const { default: app } = await import('../server/server.js').catch(err => {
            // Try without .js if it fails (depends on builder)
            return import('../server/server');
        });

        // Ensure Express handles the request
        return app(req, res);
    } catch (error: any) {
        console.error('CRITICAL_BOOT_ERROR:', error);
        res.status(500).json({
            error: 'CRITICAL_BOOT_ERROR',
            message: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
            hint: 'This usually means a module resolution issue or a top-level crash in your server code.'
        });
    }
}
