import mongoose from 'mongoose';
import { Logging } from 'shared/dist'
import config from './config';

/**
 * Database Configuration with Production Best Practices
 * Updated for Atlas MongoDB with environment-specific configurations
 */

interface DatabaseConfig {
    username: string;
    password: string;
    cluster: string;
    database: string;
    retryWrites?: boolean;
    writeConcern?: string;
    authSource?: string;
}

class DatabaseConnection {
    private static instance: DatabaseConnection;
    private isConnected: boolean = false;
    private connectionAttempts: number = 0;
    private maxRetries: number = 3;

    private constructor() {}

    public static getInstance(): DatabaseConnection {
        if (!DatabaseConnection.instance) {
            DatabaseConnection.instance = new DatabaseConnection();
        }
        return DatabaseConnection.instance;
    }

    /**
     * Build MongoDB connection URI with proper encoding for Atlas
     */
    private buildConnectionString(): string {
        const { username, password, cluster, database } = this.validateEnvironment();
        
        // Encode credentials to handle special characters
        const encodedUsername = encodeURIComponent(username);
        const encodedPassword = encodeURIComponent(password);
        
        // Atlas MongoDB connection string format (without database in path)
        const connectionString = `mongodb+srv://${encodedUsername}:${encodedPassword}@${cluster}/?retryWrites=true&w=majority`;
        
        Logging.debug('🔗 Connection string built', {
            cluster,
            database,
            environment: config.environment,
            connectionString: connectionString.replace(encodedPassword, '***')
        });
        
        return connectionString;
    }

    /**
     * Get MongoDB connection options optimized for Atlas and production
     */
    private getConnectionOptions(): mongoose.ConnectOptions {
        const isProduction = config.environment === 'production';
        const { database } = this.validateEnvironment();
        
        return {
            // Database name specification
            dbName: database,
            
            // Connection timeout settings
            serverSelectionTimeoutMS: isProduction ? 15000 : 10000, // Longer timeout for production
            socketTimeoutMS: 45000, // 45 seconds for socket timeout
            connectTimeoutMS: 15000, // 15 seconds for initial connection
            
            // Connection pool settings optimized for Atlas
            maxPoolSize: isProduction ? 20 : 10, // More connections in production
            minPoolSize: isProduction ? 5 : 2,   // Keep minimum connections alive
            maxIdleTimeMS: 30000, // Close connections after 30 seconds of inactivity
            
            // Atlas-specific settings
            retryWrites: true,
            retryReads: true,
            
            // Buffer settings
            bufferCommands: false, // Disable mongoose buffering for commands
            
            // Additional Atlas optimizations
            heartbeatFrequencyMS: 10000, // Heartbeat every 10 seconds
            family: 4, // Use IPv4, skip trying IPv6
        };
    }

    /**
     * Validate required environment variables and return config
     */
    private validateEnvironment(): DatabaseConfig {
        const username = process.env.MONGO_DB_USER;
        const password = process.env.MONGO_DB_PASSWORD;
        
        if (!username || !password) {
            throw new Error(
                'Missing required environment variables: MONGO_DB_USER and MONGO_DB_PASSWORD must be set'
            );
        }

        if (!username.trim() || !password.trim()) {
            throw new Error(
                'Invalid environment variables: MONGO_DB_USER and MONGO_DB_PASSWORD cannot be empty'
            );
        }

        return {
            username: username.trim(),
            password: password.trim(),
            cluster: config.mongo.cluster,
            database: config.mongo.database,
        };
    }

    /**
     * Setup connection event listeners with enhanced logging
     */
    private setupEventListeners(): void {
        // Connection successful
        mongoose.connection.on('connected', () => {
            this.isConnected = true;
            this.connectionAttempts = 0; // Reset attempts on successful connection
            Logging.database('✅ Connected successfully to Atlas MongoDB', {
                host: mongoose.connection.host,
                name: mongoose.connection.name,
                readyState: mongoose.connection.readyState,
                environment: config.environment,
                cluster: config.mongo.cluster
            });
        });

        // Connection disconnected
        mongoose.connection.on('disconnected', () => {
            this.isConnected = false;
            Logging.warn('⚠️ Atlas MongoDB disconnected', {
                environment: config.environment,
                cluster: config.mongo.cluster
            });
        });

        // Connection error
        mongoose.connection.on('error', (error) => {
            this.isConnected = false;
            Logging.database('❌ Atlas MongoDB connection error occurred', { 
                error: error.message,
                readyState: mongoose.connection.readyState,
                environment: config.environment,
                cluster: config.mongo.cluster,
                attempts: this.connectionAttempts
            });
        });

        // Connection reconnected
        mongoose.connection.on('reconnected', () => {
            this.isConnected = true;
            Logging.database('🔄 Reconnected successfully to Atlas MongoDB', {
                host: mongoose.connection.host,
                name: mongoose.connection.name,
                environment: config.environment
            });
        });

        // Atlas-specific events
        mongoose.connection.on('fullsetup', () => {
            Logging.database('🌐 Atlas MongoDB replica set fully connected');
        });

        // Process termination handlers
        process.on('SIGINT', this.gracefulShutdown.bind(this));
        process.on('SIGTERM', this.gracefulShutdown.bind(this));
        process.on('SIGUSR2', this.gracefulShutdown.bind(this)); // For nodemon
    }

    /**
     * Graceful shutdown handler
     */
    private async gracefulShutdown(signal: string): Promise<void> {
        Logging.info(`🛑 Received ${signal}. Gracefully shutting down Atlas MongoDB connection...`);
        
        try {
            await mongoose.connection.close();
            Logging.info('✅ Atlas MongoDB connection closed gracefully');
            process.exit(0);
        } catch (error) {
            Logging.error('❌ Error during Atlas MongoDB shutdown:');
            Logging.error(error);
            process.exit(1);
        }
    }

    /**
     * Connect to Atlas MongoDB with retry logic
     */
    public async connect(): Promise<void> {
        const timer = Logging.startTimer();
        
        try {
            this.connectionAttempts++;
            
            Logging.database('🚀 Initiating Atlas MongoDB connection', {
                cluster: config.mongo.cluster,
                database: config.mongo.database,
                environment: config.environment,
                attempt: this.connectionAttempts,
                maxRetries: this.maxRetries
            });
            
            // Build connection string
            const connectionString = this.buildConnectionString();
            
            // Setup event listeners (only once)
            if (this.connectionAttempts === 1) {
                this.setupEventListeners();
            }
            
            // Set mongoose options for production
            mongoose.set('strictQuery', false); // Prepare for Mongoose 7
            
            // Enable debug mode in development
            if (config.environment !== 'production') {
                mongoose.set('debug', (collectionName: string, method: string, query: any) => {
                    Logging.debug(`🐛 Mongoose: ${collectionName}.${method}`, { query });
                });
                Logging.debug('🐛 Mongoose debug mode enabled');
            }

            // Connect to Atlas MongoDB
            await mongoose.connect(connectionString, this.getConnectionOptions());
            
            timer.done({ 
                message: 'Atlas MongoDB connection established',
                environment: config.environment,
                cluster: config.mongo.cluster,
                database: config.mongo.database
            });
            
        } catch (error) {
            this.isConnected = false;
            const errorMessage = error instanceof Error ? error.message : String(error);
            
            Logging.database('❌ Atlas MongoDB connection failed', { 
                error: errorMessage,
                environment: config.environment,
                cluster: config.mongo.cluster,
                attempt: this.connectionAttempts,
                maxRetries: this.maxRetries
            });
            
            timer.done({ 
                message: 'Atlas MongoDB connection failed', 
                error: errorMessage,
                attempt: this.connectionAttempts
            });
            
            // Retry logic
            if (this.connectionAttempts < this.maxRetries) {
                const retryDelay = 2000 * this.connectionAttempts; // Exponential backoff
                Logging.warn(`🔄 Retrying Atlas MongoDB connection in ${retryDelay}ms...`);
                
                await new Promise(resolve => setTimeout(resolve, retryDelay));
                return this.connect(); // Recursive retry
            }
            
            // Re-throw the error after all retries failed
            throw new Error(`Atlas MongoDB connection failed after ${this.maxRetries} attempts: ${errorMessage}`);
        }
    }

    /**
     * Check if database is connected
     */
    public isDbConnected(): boolean {
        return this.isConnected && mongoose.connection.readyState === 1;
    }

    /**
     * Get connection health status with Atlas-specific information
     */
    public getConnectionStatus(): { 
        connected: boolean; 
        readyState: number; 
        host?: string; 
        name?: string;
        environment: string;
        cluster: string;
        database: string;
        attempts: number;
    } {
        return {
            connected: this.isConnected,
            readyState: mongoose.connection.readyState,
            host: mongoose.connection.host,
            name: mongoose.connection.name,
            environment: config.environment,
            cluster: config.mongo.cluster,
            database: config.mongo.database,
            attempts: this.connectionAttempts,
        };
    }

    /**
     * Disconnect from Atlas MongoDB
     */
    public async disconnect(): Promise<void> {
        try {
            await mongoose.disconnect();
            this.isConnected = false;
            this.connectionAttempts = 0;
            Logging.info('✅ Atlas MongoDB disconnected successfully');
        } catch (error) {
            Logging.error('❌ Error disconnecting from Atlas MongoDB:');
            Logging.error(error);
            throw error;
        }
    }

    /**
     * Reset connection state (useful for testing)
     */
    public reset(): void {
        this.isConnected = false;
        this.connectionAttempts = 0;
    }
}

export default DatabaseConnection; 