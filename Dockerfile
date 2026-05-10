# scry-augur — minimal Node 22 alpine image.
#
# Stateless aggregator: pulls public threat-intel feeds and writes to the
# scry Postgres. No persistent local state, no inbound ports — this is a
# scheduled puller, not a server. Smoke scripts are NOT copied; they run
# from a dev workstation against the live PG via SSH tunnel.

FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY schema ./schema

USER node

# No EXPOSE — augur has no inbound surface.

# Liveness check: a Node one-liner that confirms the process can reach
# the configured Postgres (the only external dep). Cheap; runs every
# 60s. Returns 0 on a successful SELECT 1.
HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
  CMD node -e "import('pg').then(({default:p})=>{const c=new p.Client({connectionString:process.env.PG_URL});c.connect().then(()=>c.query('SELECT 1')).then(()=>{c.end();process.exit(0)}).catch(()=>process.exit(1))})"

CMD ["node", "src/index.js"]
