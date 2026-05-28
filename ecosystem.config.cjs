// ecosystem.config.cjs
// PM2 process configuration for NetShare relay
// Usage: pm2 start ecosystem.config.cjs

module.exports = {
  apps: [{
    name:   'netshare-relay',
    script: 'server.js',
    cwd:    '/opt/netshare-relay',
    env: {
      PORT:         '4000',
      ADMIN_KEY:    'CHANGE_THIS_PASSWORD',  // ← change before deploying!
      WG_IFACE:     'wg0',
      VPS_ENDPOINT: '1.2.3.4:51820',        // ← change to your VPS public IP
      MAX_CLIENTS:  '10',
      DATA_FILE:    '/opt/netshare-relay/data.json',
    },
    // Auto-restart on crash, keep logs
    autorestart: true,
    max_memory_restart: '200M',
    error_file:  '/var/log/netshare-error.log',
    out_file:    '/var/log/netshare-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
  }],
};
