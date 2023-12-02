module.exports = {
  apps: [
    {
      name: "lc_backend",
      script: "./app.js",
      watch: false,
      ignore_watch: ["node_modules"],
      instances: "max",
      env: {
        NODE_ENV: "development",
      },
      env_production: {
        NODE_ENV: "production",
      },
    },
  ],
};
