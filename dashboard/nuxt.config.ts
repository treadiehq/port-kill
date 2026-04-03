// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  devtools: { enabled: true },
  modules: [
    '@nuxtjs/tailwindcss',
    '@nuxtjs/color-mode',
    '@vueuse/nuxt'
  ],
  colorMode: {
    preference: 'dark', // default value of $colorMode.preference
    fallback: 'dark', // fallback value if not system preference found
    hid: 'nuxt-color-mode-script',
    globalName: '__NUXT_COLOR_MODE__',
    componentName: 'ColorScheme',
    classPrefix: '',
    classSuffix: '',
    storageKey: 'nuxt-color-mode'
  },
  runtimeConfig: {
    // Private keys (only available on server-side)
    portKillBinaryPath: process.env.PORT_KILL_BINARY_PATH || '../target/release/port-kill-console',
    remoteHost: process.env.REMOTE_HOST || '',
    remoteMode: process.env.REMOTE_MODE === 'true',
    
    // Public keys (exposed to client-side)
    public: {
      apiBase: process.env.API_BASE || 'http://localhost:3000/api',
      remoteMode: process.env.REMOTE_MODE === 'true',
      remoteHost: process.env.REMOTE_HOST || ''
    }
  },
  nitro: {
    experimental: {
      wasm: true
    }
  }
})