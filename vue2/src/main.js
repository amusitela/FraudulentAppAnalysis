import Vue from 'vue'
import ElementUI from 'element-ui';
import 'element-ui/lib/theme-chalk/index.css';
import './assets/button.css'
import './assets/tabs.css'
import './assets/input.css'
import './assets/upload.css'
import './assets/icon.css'
import './assets/tag.css'
import App from './App.vue'
import router from './router/index.js'
import axios from 'axios'
Vue.prototype.$axios = axios
axios.defaults.baseURL = '/api/'

Vue.config.productionTip = false
Vue.use(ElementUI);

new Vue({
  render: h => h(App),
  router:router
}).$mount('#app')
