import dotenv from 'dotenv';

dotenv.config();

// ====================================
// 🔧 APPLICATION CONFIGURATION
// ====================================

const appName = "sharefi";

// DECLARE ALL VARIABLES
const MONGO_DB_USER = process.env.MONGO_DB_USER || '';
const MONGO_DB_PASSWORD = process.env.MONGO_DB_PASSWORD || '';
const NODE_ENV = process.env.NODE_ENV || 'development';
const SERVER_PORT = process.env.PORT ? Number(process.env.PORT) : 3001;

// ====================================
// 🗄️ DATABASE CONFIGURATION
// ====================================

// Atlas MongoDB Clusters
const DEVELOPMENT_CLUSTER = 'development.c6kvcji.mongodb.net';
const PRODUCTION_CLUSTER = process.env.MONGO_PRODUCTION_CLUSTER || 'production.c6kvcji.mongodb.net';

// Build connection strings for different environments
const buildMongoUrl = (cluster: string, database: string): string => {
    return `mongodb+srv://${MONGO_DB_USER}:${MONGO_DB_PASSWORD}@${cluster}/${database}`;
};

// Environment-specific configurations
const MONGO_URL_DEVELOPMENT = buildMongoUrl(DEVELOPMENT_CLUSTER, appName);
const MONGO_URL_PRODUCTION = buildMongoUrl(PRODUCTION_CLUSTER, appName);
const MONGO_URL_LOCAL = buildMongoUrl(DEVELOPMENT_CLUSTER, `${appName}_local`);

// ====================================
// 📦 CONFIG OBJECT
// ====================================

//CREATE CONFIG OBJECT
const config = {
    mongo: {
        url: 'mongodb+srv://...',      // Full connection string
        cluster: 'development.c6kvcji.mongodb.net',  // Cluster info
        database: 'sharefi',           // Database name
    },
    server: { port: 5000 },
    environment: 'development'         // Current environment
};

// ====================================
// 🌍 ENVIRONMENT CONFIGURATION
// ====================================

//CHECK FOR ENVIRONMENT
if (NODE_ENV === 'production') {
    config.mongo.url = MONGO_URL_PRODUCTION;
    config.mongo.cluster = PRODUCTION_CLUSTER;
    config.mongo.database = appName;
    config.server.port = SERVER_PORT;
} else if (NODE_ENV === 'local') {
    config.mongo.url = MONGO_URL_LOCAL;
    config.mongo.cluster = DEVELOPMENT_CLUSTER;
    config.mongo.database = `${appName}_local`;
    config.server.port = SERVER_PORT;
} else {
    // Default to development environment
    config.mongo.url = MONGO_URL_DEVELOPMENT;
    config.mongo.cluster = DEVELOPMENT_CLUSTER;
    config.mongo.database = appName;
    config.server.port = SERVER_PORT;
}

//EXPORT
export default config;
