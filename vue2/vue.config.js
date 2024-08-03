'use strict'
const path = require('path')

function resolve(dir) {
  return path.join(__dirname, dir)
}

module.exports = {
  publicPath: '/', // 部署在根路径下
  lintOnSave: false,
  devServer: {
    host: 'localhost',
    port: 8001,
    client: {
      webSocketURL: 'ws://192.168.100.143/ws',
    },
    proxy: {
      '/api': {
        target: 'http://192.168.100.143:8000',
        changeOrigin: true,
        pathRewrite: {
          '^/api': ''
        }
      },
      '/media': {
        target: 'http://192.168.100.143:8000',
        changeOrigin: true,
        pathRewrite: {
          //'^/media': ''
        }
      }
    }
  },
  configureWebpack: {
    resolve: {
      alias: {
        '@': resolve('src'),
      }
    }
  }
};
