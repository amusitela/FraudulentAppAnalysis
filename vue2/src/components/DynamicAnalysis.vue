<template>
  <div class="body">
    <div class="my-header">
      <div class="logo"></div>
      <div class="menu-bar">
        <span class="menu-item">文档</span>
        <span class="menu-item">关于我们</span>
      </div>
    </div>

    <div class="my-main">
      <el-steps :active="active" finish-status="success" :align-center="true" style="margin-top: 20px; margin-bottom: 30px;">
      <el-step title="步骤 1"></el-step>
      <el-step title="步骤 2"></el-step>
      <el-step title="步骤 3"></el-step>
      </el-steps>

      <div v-show="active==0||active == 1" style="margin-top: 100px;">
        <h1>连接虚拟机</h1>
          <div class="input-data">
            <input type="text" v-model="ipAddress" required>
            <div class="underline"></div>
            <label>虚拟机ip地址</label>
          </div>
        <el-button style="width: 150px; margin-top: 50px" type="primary" @click="getConnected" plain>下一步</el-button>
        <p>不需要使用手动模式请填写127.0.0.1:5555</p>
      </div>

      <el-dialog
          :visible.sync="dialogVisible"
          width="400px"
          :close-on-click-modal="false"
          :before-close="beforeClose"
          style="margin-top: 200px;">
          <h2>请选择动态解析的方式</h2>
          <span slot="footer" class="dialog-footer">
            <el-button type="success" @click="autoWay" >自 动</el-button>
            <el-button type="primary" @click="handWay">手 动</el-button>
          </span>
      </el-dialog>
      <!-- 手动 -->
      <div v-show="active==3">
        <div style="width: 350px; height: 600px; border: solid 2px; margin-left: 320px">虚拟机</div>
        <div style="margin-top: 30px;">
        <span><el-button type="warning" @click="takeScreen" style="margin-right: 30px">截 图</el-button></span>
        <span><el-button type="primary" @click="autoCapture" style="margin-right: 30px">自动抓包</el-button></span>
        <span><el-button type="success" @click="startCapture" style="margin-right: 30px">开始抓包</el-button></span>
        <span><el-button type="danger" @click="endCapture" >结束抓包</el-button></span>
      </div>
      </div>


    </div>
  </div>
</template>

<script>
import axios from 'axios';
import { Loading } from 'element-ui'
export default {
name: 'DynamicAnalysis',
  data() {
    return {
      active: 0,
      md5: this.$route.params.md5,
      ipAddress: '',
      dialogVisible: false,
      secretKey:process.env.VUE_APP_APIKEY,
      maxAttempt:process.env.VUE_APP_MAX_ATTEMPT,
      attempts: 0,
    };
  },
  created(){
    this.attempts = 1;
  },
  methods: {
    getConnected(){
      console.log(this.md5)
      this.active = 1;
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在连接，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const headers = {
        'Authorization': this.secretKey
      };
      const formData = new FormData();
        formData.append('identifier',this.ipAddress);
        axios.post('/api/v1/android/mobsfy', formData, { headers })
         .then(res => {
          console.log(res.data);
          downloadLoadingInstance.close();
          if('error' in res.data){
            this.$message({
            message: '连接失败：'+ res.data.error,
            type: 'error'
          });
          }else{
              this.$message({
              message: '连接成功',
              type: 'success'
            });
            this.dialogVisible = true;
            this.active = 2;
          }
          
        })
        .catch(error => {
          downloadLoadingInstance.close();
          console.error('Error:', error);
          this.$message({
            message: '连接失败:'+error,
            type: 'error'
          });
        });
       
      //成功后this.dialogVisible = false;
    },
    beforeClose(){
      this.active = 0;
      this.dialogVisible = false;
    },
    autoWay(){
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在分析，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const headers = {
        'Authorization': this.secretKey
      };
      const formData = new FormData();
        formData.append('hash',this.md5);
        formData.append('maxAttempts',this.maxAttempt);
        axios.post('/api/v1/dynamic/my_analysis', formData, { headers })
         .then(res => {
          console.log(res.data);
          downloadLoadingInstance.close();
          this.dialogVisible = true;
          if('error' in res.data){
            this.$message({
            message: '动态解析失败：'+ res.data.error,
            type: 'error'
          });
          }else{
            this.$message({
            message: '动态解析成功！识别结果为：'+res.data.message,
            type: 'success'
          });
          }
          this.active = 3;
          this.dialogVisible = false;
        })
        .catch(error => {
          downloadLoadingInstance.close();
          console.error('Error:', error);
          this.$message({
            message: '动态解析失败:该 APK 是否与 Android VM/模拟器兼容？或者使用手动模式试试。详细请前往控制台查看',
            type: 'error'
          });
        });
        
      // 成功后this.dialogVisible = false;
    },
    handWay(){
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在安装apk，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const headers = {
        'Authorization': this.secretKey
      };
      const formData = new FormData();
        formData.append('hash',this.md5);
        axios.post('/api/v1/dynamic/hand_analysis', formData, { headers })
         .then(res => {
          console.log(res.data);
          downloadLoadingInstance.close();
          if('error' in res.data){
            this.$message({
              message: '安装失败：' + res.data.error,
              type: 'error'
            });
          }
          else{
            this.$message({
              message: '安装结果为：' + res.data.message,
              type: 'success'
            });
          }
        })
        .catch(error => {
          downloadLoadingInstance.close();
          this.$message({
            message: '此 APK 无法安装。该 APK 是否与 Android VM/模拟器兼容？',
            type: 'error'
          });
        });
      this.active = 3;
      this.dialogVisible = false;

    },
    takeScreen(){

     let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在处理，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const headers = {
        'Authorization': this.secretKey
      };
      console.log(this.attempts);
      const formData = new FormData();
        formData.append('maxAttempts',this.maxAttempt);
        formData.append('attempts',this.attempts);
        formData.append('hash',this.md5);
        axios.post('/api/v1/dynamic/take_screen', formData, { headers })
         .then(res => {
          console.log(res.data);
          downloadLoadingInstance.close();
          if('error' in res.data){
            this.$message({
                message: '失败：'+res.data.error,
                type: 'error'
              }); 
        }
        else{
            if(this.attempts == this.maxAttempt){
            this.attempts = 1;
            this.$message({
              message: '识别结果为：' + res.data.message,
              type: 'success'
            });
          }
          else{
            this.$message({
              message: `第${this.attempts}次截图成功`,
              type: 'success'
            });
            this.attempts = this.attempts+1;
        }
        }
        })
        .catch(error => {
          downloadLoadingInstance.close();
          this.$message({
            message: '截图失败:'+error,
            type: 'error'
          });
        });

    },
    startCapture(){
      this.$message({
            message: '开始抓包...',
            type: 'success'
          });
      const headers = {
        'Authorization': this.secretKey
      };
      const formData = new FormData();
        formData.append('hash',this.md5);
        axios.post('/api/v1/dynamic/start_capture', formData, { headers })
        .then(res=>{
          if('error' in res.data){
            this.$message({
            message: '开抓包失败：'+ res.data.error,
            type: 'error'
          });
          }else{
            this.$message({
            message: '开始抓包成功！请手动操作应用10秒以上',
            type: 'success'
          });
          }
        })
        .catch(error => {
          console.error('Error:', error);
          this.$message({
            message: '抓包失败:'+error,
            type: 'error'
          });
        });

    },
    endCapture(){
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在生成IP报告，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const headers = {
        'Authorization': this.secretKey
      };
      const formData = new FormData();
        formData.append('hash',this.md5);
        axios.post('/api/v1/dynamic/end_capture', formData, { headers })
         .then(res => {
          console.log(res.data);
          downloadLoadingInstance.close();
          if('error' in res.data){
            this.$message({
            message: '生成失败：'+ res.data.error,
            type: 'error'
          });
          }else{
            this.$message({
            message: '生成IP报告成功！请查看历史记录中的相应报告',
            type: 'success'
          });
          }
          
        })
        .catch(error => {
          downloadLoadingInstance.close();
          console.error('Error:', error);
          this.$message({
            message: '生成报告失败:'+ error,
            type: 'error'
          });
        });
    },
    autoCapture(){
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在自动抓包，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const headers = {
        'Authorization': this.secretKey
      };
      const formData = new FormData();
        formData.append('hash',this.md5);
        axios.post('/api/v1/dynamic/auto_capture', formData, { headers })
         .then(res => {
          console.log(res.data);
          downloadLoadingInstance.close();
          if('error' in res.data){
            this.$message({
            message: '抓包失败：'+ res.data.error,
            type: 'error'
          });
          }else{
            this.$message({
            message: '抓包成功！请查看历史记录中的相应报告',
            type: 'success'
          });
          }
          
        })
        .catch(error => {
          downloadLoadingInstance.close();
          console.error('Error:', error);
          this.$message({
            message: '生成报告失败:先检查apk是否和VM兼容或者使用手动抓包',
            type: 'error'
          });
        });
    }
  }
};
</script>

<style lang="scss" scoped>
.body {
    margin: 0;
    padding: 0;
    width: 1900px;
    height: 98vh;
    box-sizing: border-box;
    font-weight: 400;
    // font-style: normal;

    font-family: 'Open Sans', sans-serif;
    // position: relative;
    position: relative;
    // background: linear-gradient(245.59deg, #4d9559 0%, #38703d 28.53%, #133917 75.52%);
    background-color: #F4F6F9;
    
}
.my-header{
  position: relative;
  height: 45px;
  width: 1900px;
  font-size: 20px;
  padding-top: 10px;
  background: linear-gradient(245.59deg, #2D7BFD 0%, #2D7BFD 28.53%, #2D7BFD 75.52%);
  border-radius: 5px;
  box-shadow: 0 2px 2px rgba(0,0,0,0.19), 0 2px 2px rgba(0,0,0,0.23);
  .logo{
    position: absolute;
    left: 0;
  }
  .menu-bar{
    position: absolute;
    right: 0;
    .menu-item{
      margin-right: 40px;
      color: white;
      text-decoration: none;
      padding-bottom: 4px;
      font-size: 18px;
      border-bottom: 2px solid transparent;
      transition: all 0.3s ease;
    }
    .menu-item:hover {
    border-bottom: 2px solid white;
    }
    }
}
.my-main {
  // height: 500px;
  max-width: 1000px;
  min-width: 1000px;
  max-height: 800px;
  min-height: 800px;
  position: absolute;
  // top: 25; /* 向上移动自身高度的50% */  
  left: 440px; /* 向左移动自身宽度的50% */  
  margin-top: 20px;
  // transform: translate(-50%, -50%); /* 通过transform调整位置，使其真正居中 */
  background-color: #FFFFFF;
  border-radius: 10px;
  box-shadow: 0 0 2px rgba(0, 0, 0, 0.5);
  padding: 20px;
}
.input-data{
  position: relative;
  width: 450px;
  height: 40px;
  margin-left: 260px;
  margin-top: 40px;
}
.input-data input{
  width: 100%;
  height: 100%;
  border: none;
  font-size: 17px;
  border-bottom: 2px solid #c0c0c0;
}
.input-data input:focus {
  outline: none;
}
.input-data input:focus ~ label,
.input-data input:valid ~ label{
  transform: translateY(-25px);
  font-size: 15px;
  color: red;
}
.input-data input:valid:not(:focus) ~ label,
.input-data label{
  position: absolute;
  bottom: 10px;
  left: 0px;
  color: #808080;
  pointer-events: none;
  transition: all 0.3s ease;
}
.input-data .underline{
  position: absolute;
  bottom: -4px;
  height: 2px;
  width: 100%;
  background-color: red;
  transform: scaleX(0);
  transition: all 0.8s ease;
}
.input-data input:focus ~ .underline,
.input-data input:valid ~ .underline{
  transform: scaleX(1);
} 
.input-data input:valid:not(:focus) ~ .underline{
  transform: scaleX(0);
}
</style>