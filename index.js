const bluebird = require('bluebird');
const Redis = require('ioredis');

const host = process.env.CACHE_HOST || 'localhost';
const port = process.env.CACHE_PORT ? parseInt(process.env.CACHE_PORT) : 6379;

const logger = global.logger;

function getClusterNodes() {
    let nodes = [];
    //format: 127.0.0.1,127.0.0.2:8990 results in 127.0.0.1:6379 and 127.0.0.2:8990 respectively
    let clusterNodes = process.env.CACHE_CLUSTER.split(',');
    clusterNodes.map(node => {
        nodes.push({
            host: node.split(':')[0],
            port: node.split(':')[1] || '6379',
        });
    });
    return nodes;
}

function AuthCache() {
    this.client = null;
    if (process.env.CACHE_CLUSTER) {
        logger.info('Connecting to cache cluster');
        logger.info('Cache cluster nodes :: ', JSON.stringify(getClusterNodes()));
        this.client = new Redis.Cluster(getClusterNodes());
    } else {
        logger.info('Connecting to standalone cache');
        this.client = new Redis(port, host);
    }
    this.client = bluebird.promisifyAll(this.client);
    this.client.on('error', function (err) {
        logger.error(err.message);
    });
    this.client.on('connect', function () {
        logger.info('Cache client connected');
    });
}

AuthCache.prototype.blacklistToken = async function (token, ttl) {
    await this.client.setAsync(`token:${token}`, 'BLACKLIST', 'EXAT', ttl);
}

AuthCache.prototype.isTokenBlacklisted = async function (token) {
    const data = await this.client.existsAsync(`token:${token}`);
    if (data) {
        return true;
    }
    return false;
}

AuthCache.prototype.setUserPermissions = async function (username, permissions) {
    await this.client.setAsync(`perm:${username}`, JSON.stringify(permissions));
}

AuthCache.prototype.getUserPermissions = async function (username) {
    return await this.client.getAsync(`perm:${username}`);
}

AuthCache.prototype.unsetUserPermissions = async function (username) {
    await this.client.del(`perm:${username}`);
}

AuthCache.prototype.setHeartbeatID = async function (token, heartbeatId, ttl) {
    await this.client.setAsync(`hb:${token}:${heartbeatId}`, 'WHITELIST', 'EXAT', ttl);
}

AuthCache.prototype.unsetHeartbeatID = async function (token, heartbeatId) {
    await this.client.del(`hb:${token}:${heartbeatId}`);
}

AuthCache.prototype.isHeartbeatValid = async function (token, heartbeatId) {
    const data = await this.client.existsAsync(`hb:${token}:${heartbeatId}`);
    if (data) {
        return true;
    }
    return false;
}

module.exports = AuthCache;