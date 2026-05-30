// ecosystem.config.cjs
// PM2 process configuration for NetShare relay
// Usage: pm2 start ecosystem.config.cjs

module.exports = {
  apps: [{
    name:   'netshare-relay',
    script: 'server.js',
    cwd:    '/opt/netshare-relay',
    env: {
      PORT:              '4000',
      ADMIN_KEY:         'Awachnediraphael@1',
      WG_IFACE:          'wg0',
      VPS_ENDPOINT:      '178.105.190.123:51820',
      MAX_CLIENTS:       '10',
      DATA_FILE:         '/opt/netshare-relay/data.json',

      // Data-saving settings
      CLIENT_KEEPALIVE:  '60',   // seconds between client keepalives (was 25, saves ~90KB/day per client)
      SESSION_TIMEOUT_H: '24',   // hours before host session auto-expires
      MAX_DATA_MB_DAY:   '50',   // MB per client per day before warning shows in admin panel
    },
    // Auto-restart on crash, keep logs
    autorestart: true,
    max_memory_restart: '200M',
    error_file:  '/var/log/netshare-error.log',
    out_file:    '/var/log/netshare-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
  }],
};
