import express from 'express';
import http from 'http';
import config from './config/config';
import Logging from './library/Logging';
import DatabaseConnection from './config/database';
import { router as v1 } from './routes/v1/index';
import MailService from './services/mailService';
import HttpError from './utils/httpError';
import { crateRole } from './controllers/role.controller';
import { initializeAxiosService } from './services/axiosService';

const router = express();

//CONNECTION TO MONGOOSE DATABASE WITH PRODUCTION BEST PRACTICES
const initializeDatabase = async (): Promise<void> => {
    try {
        // Clear terminal and show startup message
        Logging.clearAndStart('Initializing User Management System...');
        
        const db = DatabaseConnection.getInstance();
        await db.connect();
        
        Logging.separator('DATABASE CONNECTED');
        Logging.startup(`Server starting in ${process.env.NODE_ENV || 'default'} environment`);
        
        // Initialize roles after successful DB connection
        crateRole();
        
        // Start the server
        await StartServer();
    } catch (error) {
        Logging.error('💥 Database initialization failed', { error: error.message });
        process.exit(1);
    }
};

//ONLY START THE SERVER IF MONGOOSE IS CONNECTED
const StartServer = async () => {
    try {
        // Initialize User Service (in-memory sessions)
        Logging.info('🔧 Initializing User Session Micro-Service...');
        // UserService will be initialized automatically when AxiosService starts
        Logging.info('✅ User Session Service ready');

        initializeAxiosService();

        //MAIL SMTP CONNECTION
        Logging.info('📧 Connecting with SMTP Server...');
        const mailService = MailService.getInstance();
        if (process.env.NODE_ENV === 'local') {
            await mailService.createLocalConnection();
        } else if (process.env.NODE_ENV === 'production') {
            await mailService.createConnection();
        }
        Logging.info('✅ SMTP Server Connected and verified');

        // Enhanced request logging middleware
        router.use((req, res, next) => {
            const startTime = Date.now();
            
            // Log incoming request
            Logging.http(`📥 ${req.method} ${req.url}`, {
                method: req.method,
                url: req.url,
                ip: req.socket.remoteAddress,
                userAgent: req.get('User-Agent'),
                contentType: req.get('Content-Type')
            });

            // Log response when finished
            res.on('finish', () => {
                const responseTime = Date.now() - startTime;
                const level = res.statusCode >= 400 ? 'warn' : 'http';
                
                Logging.request(
                    req.method,
                    req.url,
                    res.statusCode,
                    responseTime,
                    req.socket.remoteAddress
                );
            });
            
            next();
        });

        router.use(express.urlencoded({ extended: true }));
        router.use(express.json());

        //RULES OF OUR APIS
        router.use((req, res, next) => {
            res.header('Access-Control-Allow-Origin', '*');
            res.header(
                'Access-Control-Allow-Headers',
                'Origin,X-Requested-with,Content-Type,Accept,Authorization'
            );

            if (req.method == 'OPTIONS') {
                res.header(
                    'Access-Control-Allow-Methods',
                    'PUT,POST,PATCH,DELETE,GET'
                );
                return res.status(200).json({});
            }
            next();
        });

        //API ROUTES WITH VERSION
        router.use('/api', v1);

        //API HEALTHCHECK WITH DATABASE STATUS
        router.get('/ping', (req, res, next) => {
            const db = DatabaseConnection.getInstance();
            const dbStatus = db.getConnectionStatus();
            
            const response = { 
                message: dbStatus.connected ? 'pong' : 'service unavailable',
                database: {
                    connected: dbStatus.connected,
                    readyState: dbStatus.readyState,
                    host: dbStatus.host,
                    name: dbStatus.name
                },
                timestamp: new Date().toISOString()
            };

            if (dbStatus.connected) {
                Logging.debug('🏓 Health check - ping successful', { endpoint: '/ping' });
            } else {
                Logging.warn('⚠️ Health check - database not connected', { endpoint: '/ping' });
            }
            
            res.status(dbStatus.connected ? 200 : 503).json(response);
        });

        //API HEALTH CHECK FOR DATABASE CONNECTIVITY
        router.get('/health', (req, res, next) => {
            const db = DatabaseConnection.getInstance();
            const dbStatus = db.getConnectionStatus();
            const isHealthy = dbStatus.connected && dbStatus.readyState === 1;
            
            const response = {
                status: isHealthy ? 'healthy' : 'unhealthy',
                database: dbStatus,
                uptime: process.uptime(),
                timestamp: new Date().toISOString(),
                environment: process.env.NODE_ENV
            };

            if (isHealthy) {
                Logging.debug('✅ Comprehensive health check passed', { endpoint: '/health' });
            } else {
                Logging.warn('❌ Comprehensive health check failed', { 
                    endpoint: '/health',
                    dbStatus: dbStatus 
                });
            }
            
            res.status(isHealthy ? 200 : 503).json(response);
        });

        //API MAIN ROUTER "/"
        router.get('/', (_, res) => {
            Logging.debug('🏠 Root endpoint accessed');
            res.status(200).json({
                success: true,
                message: 'You are on node-typescript-boilderplate. You should not have further access from here.',
            });
        });

        //API ERROR HANDLING
        router.use((req, res, next) => {
            const error = new Error('not found');
            Logging.warn(`🔍 Route not found: ${req.method} ${req.url}`, {
                method: req.method,
                url: req.url,
                ip: req.socket.remoteAddress
            });
            return res.status(404).json({ success: false, message: error.message });
        });

        //HANDLE ALL ERRORS THROWN BY CONTROLLERS
        router.use(function (err: any, req: any, res: any, next: any) {
            if (err instanceof HttpError) {
                Logging.warn('⚠️ HTTP Error occurred', {
                    title: err.opts.title,
                    detail: err.opts.detail,
                    code: err.opts.code,
                    url: req.url,
                    method: req.method
                });
                return err.sendError(res);
            } else {
                Logging.error('💥 Unhandled error occurred', {
                    error: err.message,
                    stack: err.stack,
                    url: req.url,
                    method: req.method,
                    ip: req.socket?.remoteAddress
                });
                return res.status(500).json({
                    error: {
                        title: 'general_error',
                        detail: 'An error occurred, Please retry again later',
                        code: 500,
                    },
                });
            }
        });

        //START SERVER
        const server = http.createServer(router);
        
        server.listen(config.server.port, () => {
            // Display beautiful startup banner
            Logging.banner(
                'Node TypeScript Boilerplate',
                '1.0.0',
                config.server.port
            );
            
            Logging.startup(`Server is running on port ${config.server.port}`, {
                port: config.server.port,
                environment: process.env.NODE_ENV || 'default',
                nodeVersion: process.version
            });
            
            // Enhanced terminal output for development
            Logging.separator('DEVELOPMENT URLS');
            Logging.forceOutput(`🌐 Server: http://localhost:${config.server.port}`, 'green');
            Logging.forceOutput(`❤️ Health: http://localhost:${config.server.port}/health`, 'cyan');
            Logging.forceOutput(`🏓 Ping: http://localhost:${config.server.port}/ping`, 'yellow');
            Logging.forceOutput(`🔌 API: http://localhost:${config.server.port}/api/v1`, 'blue');
            Logging.separator();
            

        });

        // Graceful shutdown handling
        process.on('SIGTERM', () => {
            Logging.shutdown('SIGTERM received, shutting down gracefully');
            server.close(() => {
                Logging.shutdown('Process terminated gracefully');
                process.exit(0);
            });
        });

        process.on('SIGINT', () => {
            Logging.shutdown('SIGINT received, shutting down gracefully');
            server.close(() => {
                Logging.shutdown('Process terminated gracefully');
                process.exit(0);
            });
        });

    } catch (error) {
        Logging.error('💥 Failed to start server', { error: error.message });
        process.exit(1);
    }
};

// Initialize database and start server
initializeDatabase();
