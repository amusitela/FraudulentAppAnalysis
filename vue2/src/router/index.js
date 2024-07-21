import Vue from 'vue'
import VueRouter from 'vue-router'

 //Vue中使用router插件
Vue.use(VueRouter)

 //路由配置，配置路由路径与组件的对应关系
const routes = [       
  {
    path: '/',
    redirect: '/home'
  }, 
  {
    path: '/home',
    name: 'HomePage',
    component: () => import('../components/HomePage.vue')
  },
  {
    path: '/DynamicAnalysis/:md5',
    name: 'DynamicAnalysis',
    component: () => import('../components/DynamicAnalysis.vue')
  },
  {
    path: '/test',
    name: 'demo',
    component: () => import('@/components/demo.vue')
  },
]
 
 //新建路由实例
const router = new VueRouter({ 
  routes
})
 
 //导出路由实例，在main.js中导入使用
export default router  
