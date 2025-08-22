import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    watch: {
      usePolling: true,
      interval: 100
    },
    proxy: {
      // '/api' から始まるリクエストをプロキシの対象にする
      '/api': {
        // 転送先のコンテナを指定 (コンテナ名:ポート)
        // Docker Composeなどではサービス名になります
        target: 'http://rust:9000',

        // CORSエラーを回避するためにオリジンを変更する
        changeOrigin: true,

        // リクエストパスから '/api' を削除して転送する
        // 例: /api/users -> /users
        rewrite: (path) => path.replace(/^\/api/, ''),
    },
  }}
})
