<template>
  <div class="body">
    <div class="my-header">
      <!-- <el-row>
        <el-image :src="require('../assets/temp_logo.jpg')" :fit="'scale-down'"></el-image>
      </el-row> -->
      <div class="logo"></div>
      <div class="menu-bar">
        <span class="menu-item">文档</span>
        <span class="menu-item">关于我们</span>
      </div>
    </div>

    <div class="my-main">
      <el-tabs class="tab" v-model="activeName" :stretch="true" v-loading="loading">
        <el-tab-pane label="QR Code" name="first">
          <div class="qrcode_container">
            <el-row>
              <qrcode-capture class="hidden-but-clickable" @detect="onDetect" :multiple="false"/>
              <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">
              <form action="#">
              <input type="file" hidden>
              <img src="#" alt="qr-code">
              <div class="content">
              <i class="fas fa-cloud-upload"></i>
              <p>点击这里上传二维码</p>
              </div>
              </form>
            </el-row>

          </div>
        </el-tab-pane>
        <el-tab-pane label="URL" name="second">
          <div class="inner">
            <el-row>
              <svg xmlns="http://www.w3.org/2000/svg" height="70" viewBox="0 0 746 525">
                <path style="fill: #8997b4"
                  d="M596.5 241h-90.2c-.3-11.5-1.1-22.8-2.2-34h-30.2c1.2 11.1 2 22.5 2.3 34H386v-34h-30v34h-90.2c.4-11.5 1.1-22.9 2.3-34h-30.2c-1.1 11.1-1.8 22.5-2.2 34h-90.2c.8-11.5 2.4-22.9 4.8-34h-30.7c-3.1 16-4.7 32.4-4.7 49 0 68.4 26.6 132.7 75 181 48.4 48.4 112.6 75 181 75s132.7-26.6 181-75c48.4-48.4 75-112.6 75-181 0-16.6-1.6-33-4.7-49h-30.7c2.6 11.1 4.2 22.5 5 34zM171.1 361.5c-14.7-27.8-23.4-58.5-25.5-90.4h90.2c.9 31.6 4.8 62.2 11.5 90.4h-76.2zm40.1 54.3c-7.6-7.6-14.6-15.7-21.1-24.3h65.4c4.8 14.8 10.4 28.8 16.9 41.6 6.8 13.5 14.2 25.5 22.2 35.7-31-11.1-59.4-29-83.4-53zm88 3.9c-4.4-8.8-8.4-18.2-12-28.2H356v87.9c-20.7-6.9-40.8-27.8-56.8-59.7zm56.8-58.2h-77.9c-7.1-27.8-11.3-58.5-12.3-90.4H356v90.4zm30-90.5h90.2c-1 32-5.2 62.6-12.3 90.4H386V271zm0 208.4v-87.9h68.7c-3.6 9.9-7.6 19.4-12 28.2-15.9 31.9-36 52.8-56.7 59.7zm144.8-63.6c-24 24-52.4 41.9-83.4 53 8-10.2 15.5-22.1 22.2-35.7 6.4-12.8 12-26.8 16.9-41.6h65.4c-6.5 8.6-13.5 16.7-21.1 24.3zm40.1-54.3h-76.1c6.6-28.2 10.5-58.8 11.5-90.4h90.2c-2.1 31.9-10.8 62.6-25.6 90.4z">
                </path>
                <path style="fill: #20242c"
                  d="M150.4 207c4.3-19.7 11.3-38.7 20.7-56.5h76.1c-4.2 18-7.3 36.9-9.3 56.5h30.2c2.1-19.7 5.4-38.7 10-56.5H356V207h30v-56.5h77.9c4.5 17.8 7.9 36.8 10 56.5h30.2c-1.9-19.6-5.1-38.5-9.3-56.5h76.1c9.4 17.8 16.3 36.7 20.7 56.5h30.7c-9.6-49.7-33.7-95.4-70.3-132C503.7 26.6 439.4 0 371 0S238.3 26.6 190 75c-36.6 36.6-60.7 82.3-70.3 132h30.7zM530.8 96.2c7.6 7.6 14.6 15.7 21.1 24.3h-65.4c-4.8-14.8-10.4-28.8-16.9-41.6-6.8-13.5-14.2-25.5-22.2-35.7 31 11.1 59.4 29 83.4 53zM386 32.6c20.7 6.9 40.8 27.8 56.7 59.7 4.4 8.8 8.4 18.2 12 28.2H386V32.6zm-30 0v87.9h-68.7c3.6-9.9 7.6-19.4 12-28.2 15.9-31.9 36-52.8 56.7-59.7zM211.2 96.2c24-24 52.4-41.9 83.4-53-8 10.2-15.5 22.1-22.2 35.7-6.4 12.8-12 26.8-16.9 41.6h-65.4c6.5-8.6 13.5-16.7 21.1-24.3z">
                </path>
                <path style="fill: #274DD8" d="M.5 177h745v30H.5z"></path>
              </svg>
            </el-row>
            <el-row>
              <el-input v-model="url_input" placeholder="请输入URL地址"></el-input>
            </el-row>
            <el-row>
              <el-button style="width: 200px;" type="primary" @click="urlDownload" plain>下载</el-button>
            </el-row>
          </div>
        </el-tab-pane>

        <el-tab-pane label="Upload" name="third" @tab-click="getList">
          <el-dialog
            title="提示"
            :visible.sync="dialogVisible"
            :close-on-click-modal="false"
            width="400px">
            <!-- <el-switch v-model="loading"></el-switch>
                                <el-skeleton style="width: 400px; " :loading="loading" animated>
                                  <template slot="template">
                                    <el-skeleton style="width: 260px" :loading="loading" animated></el-skeleton>
                                  </template> -->

                                  <template>
                                    <div style="display: flex; flex-direction: column; align-items: flex-start; gap:10px">
                                      <div><el-tag class="tag">分析类型</el-tag>{{ uploadApkReturnData.analyzer }}</div>
                                      <div><el-tag class="tag">状态</el-tag>{{ uploadApkReturnData.status }}</div>
                                      <div><el-tag class="tag">MD5</el-tag>{{ uploadApkReturnData.hash }}</div>
                                      <div><el-tag class="tag">类型</el-tag>{{ uploadApkReturnData.scan_type }}</div>
                                      <div><el-tag class="tag">文件名</el-tag>{{ uploadApkReturnData.file_name }}</div>
                                      <div><el-tag class="tag">名单</el-tag>{{ uploadApkReturnData.list }}</div>
                                    </div>
                                  </template>
                                <!-- </el-skeleton> -->
            <span slot="footer" class="dialog-footer">
              <el-button @click="dialogVisible = false">取 消</el-button>
              <el-button type="primary" @click="staticAnalysis">静态分析</el-button>
            </span>
          </el-dialog>
          <div class="inner">
          <el-row>
              <svg xmlns="http://www.w3.org/2000/svg" height="80" fill="#ff0000" viewBox="0 0 256 170">
                <g>
                  <path style="fill: #20242c"
                    d="M71 8h80.9v29.1c0 2.2 1.8 4 4 4h30V47h8v-9.1c0-1.6-.6-3.1-1.7-4.2L161.1 1.8C160 .6 158.4 0 156.8 0H68c-2.8 0-5 2.2-5 5v42h8V8Zm88.9 4 20.5 21h-20.5V12Z">
                  </path>
                  <path style="fill: #8997b4" fill-rule="evenodd"
                    d="M185.9 161.9H71V59h-8v105.9c0 2.8 2.2 5 5 5h120.9c2.8 0 5-2.2 5-5V59h-8v102.9ZM103 63.3c.7.8 2 .9 2.8.2 1.8-1.6 4.6-3.2 8-4.5h-8.7c-.7.5-1.3 1-1.9 1.5-.9.7-.9 2-.2 2.8Zm49.5.1c.8-.8.7-2.1-.1-2.8l-1.8-1.5h-7.7c2.4 1.1 4.7 2.6 6.8 4.5.7.6 2 .6 2.8-.2Zm-41.1 51.7c-2.6-6.1-3.7-12.8-1.1-18.8 2.9-6.7 8.6-9.6 14.3-10.4 2.9-.4 5.7-.3 8.1.1 2.4.4 4.3 1.1 5.2 1.7 4.7 3.1 9.5 7.7 8.6 16.1-.1 1.1.7 2.1 1.8 2.2 1.1.1 2.1-.7 2.2-1.8 1.1-10.6-5.1-16.5-10.4-19.9-1.6-1-4-1.8-6.7-2.3-2.8-.5-6-.6-9.3-.1-6.7 1-13.8 4.5-17.4 12.8-3.2 7.4-1.7 15.4 1.1 21.9 2.8 6.6 7 12.2 9.8 15.2.7.8 2 .9 2.8.1.8-.7.9-2 .1-2.8-2.6-2.7-6.5-7.9-9.1-14ZM128 71.5c4.4-.1 11.3 1.2 17.5 4.9 6.3 3.8 12 10.2 13.9 20.3 1.2 6.1.7 10.7-1.2 13.9-1.9 3.2-5.1 4.6-8.3 4.6-3.2 0-6.5-1.3-9.1-3.3-2.6-2.1-4.7-5-5.3-8.5-.8-4.7-4.7-7.4-8.6-7.3-2 0-3.8.7-5.2 2.1-1.5 1.4-2.6 3.6-2.8 7-.4 6.6 3.6 12.4 8.7 16.8 2.5 2.1 5.1 3.9 7.4 5.1 2.3 1.2 4 1.8 4.6 1.9 1.1.1 1.8 1.1 1.7 2.2-.1 1.1-1.1 1.8-2.2 1.7-1.3-.2-3.6-1.1-6-2.4-2.4-1.3-5.4-3.2-8.1-5.6-5.5-4.7-10.7-11.7-10.1-20.1.2-4.1 1.7-7.3 3.9-9.5s5.1-3.3 7.9-3.3c5.6-.1 11.4 3.8 12.6 10.6.4 2.3 1.9 4.4 3.9 6 2 1.6 4.5 2.5 6.6 2.5 2.1 0 3.8-.8 4.9-2.7 1.2-2 1.8-5.5.7-11.1-1.7-8.7-6.6-14.2-12.1-17.5-5.6-3.4-11.7-4.5-15.4-4.4h-.1c-5.3-.2-17.6 2.1-24.3 12.1-3.2 5-4.3 11.2-4.2 17.2.1 6 1.4 11.5 2.5 14.6.4 1-.2 2.1-1.2 2.5-1 .4-2.1-.2-2.5-1.2-1.2-3.5-2.6-9.4-2.7-15.8-.1-6.4 1-13.5 4.9-19.4C108 73.8 122 71.3 128 71.5Zm5.8 42.5c3.1 3.6 8.7 6.6 18.6 6 1.1-.1 2 .8 2.1 2 0 1.1-.8 2-1.9 2.1-10.9.6-17.8-2.7-21.9-7.4-4-4.7-5-10.4-4.7-14.3 0-1.1 1-2 2.1-1.9 1.1 0 2 1 1.9 2.1-.2 3.1.6 7.7 3.8 11.4ZM95.2 83.5c-.5 1-1.8 1.3-2.7.7-1-.6-1.3-1.8-.7-2.7 4-6.5 17-19 38.2-19 18 0 30.5 12.6 34.7 18.9.6.9.3 2.2-.6 2.8-.9.6-2.2.3-2.8-.6-3.8-5.7-15.2-17.1-31.3-17.1-19.6 0-31.4 11.5-34.8 17Z"
                    clip-rule="evenodd"></path>
                  <path style="fill: #274DD8" d="M185.9 47H0v12h256V47h-70.1Z"></path>
                </g>
              </svg>
            </el-row>
            <el-row class="apk_container">
              <!-- <div class="container"> -->
                <input type="file" @change="apkUpload" id="file-input"/>
                <label for="file-input" class="apklabel">
                  <i class="fa-solid fa-arrow-up-from-bracket"></i>
                  &nbsp; 上传
                </label>
              <!-- </div> -->
            </el-row>
            <el-row>
              1、支持互联网分析模式，即支持多种APP下载（采集）方式，包括但不限于：基于APK链接下载、基于APK二维码下载、网页点击按钮下载等；
              2、支持离线分析模式，即直接上传APK安装包进行分析；
            </el-row>
          </div>
        </el-tab-pane>

        <el-tab-pane label="Black/Whitelist" name="fourth">
          <div style="display: flex; justify-content: center; flex-direction: column; align-items: center; gap: 20px; margin-top: 70px">
              <div class="wbButtonContainer">
                <label for="blacklist" class="wbLabel-w" >
                  <i class="fa-solid fa-arrow-up-from-bracket"></i>
                  &nbsp; 上传黑名单
                </label>
                <input type="file" @change="handleBlackListUpload" id="blacklist">
              </div>

              <div class="wbButtonContainer">
                <label for="whitelist" class="wbLabel-b">
                  <i class="fa-solid fa-arrow-up-from-bracket"></i>
                  &nbsp; 上传白名单
                </label>
                <input type="file" @change="handleWhiteListUpload" id="whitelist">
              </div>
          </div>
          <br>
          <el-row>
              <el-input v-model="querryInput" style="width: 700px;" placeholder="请输入查询条件，格式：白名单:MD5=111&Result=black&PackageName=1231&App=12"></el-input>
              <el-button style="width: 200px;" type="primary" @click="querryList" plain>查询</el-button>
            </el-row>
          <div ref="tableScroll" @scroll="handleScrollList" style="height: 150px; overflow: auto; margin-left: 50px">
            <el-table :data="listData" >
      <el-table-column label="APP" width="200px">
        <template slot-scope="scope">
          <div>{{ scope.row.apkName }}</div>
        </template>
      </el-table-column>

      <el-table-column label="包名" width="200px">
        <template slot-scope="scope">
          <div>{{ scope.row.packageName }}</div>
        </template>
      </el-table-column>

      <el-table-column label="名单" width="200px">
        <template slot-scope="scope">
          <div>{{ scope.row.result }}</div>
        </template>
      </el-table-column>

      <el-table-column label="MD5" width="300px">
        <template slot-scope="scope">
          <div>{{ scope.row.md5 }}</div>
        </template>
      </el-table-column>
    </el-table>
        </div>
        </el-tab-pane>

       <!--  <el-tab-pane label="Record" name="fifth">
          <div ref="tableScroll" @scroll="handleScroll" style="height: 450px; overflow: auto; margin-left: 50px">
            <el-table :data="tableData" >
      <el-table-column label="APP" width="150px">
        <template slot-scope="scope">
          <el-popover trigger="hover" placement="top">
            <el-button type="primary" @click="getStaticReport(scope.row)">Static Report</el-button>
            <el-button type="success" @click="getDynamicReport(scope.row)">Dynamic Report</el-button>
            <div slot="reference" class="name-wrapper">
              <el-tag size="medium">{{ scope.row.APP_NAME }}</el-tag>
            </div>
          </el-popover>
        </template>
      </el-table-column>

      <el-table-column label="分析结果" width="150">
        <template slot-scope="scope">
          <div>静态结果:{{ scope.row.STATIC }}</div>
          <div>动态结果:{{ scope.row.DYNAMIC }}</div>
        </template>
      </el-table-column>

      <el-table-column label="名单" width="120px">
        <template slot-scope="scope">
          <div>{{ scope.row.LIST }}</div>
        </template>
      </el-table-column>

      <el-table-column label="MD5" width="200px">
        <template slot-scope="scope">
          <div>{{ scope.row.MD5 }}</div>
        </template>
      </el-table-column>

      <el-table-column label="扫描日期" width="120px">
        <template slot-scope="scope">
          <div>{{ scope.row.TIMESTAMP }}</div>
        </template>
      </el-table-column>

      <el-table-column label="操作" width="120px">
        <template slot-scope="scope">
          <div style="display: flex; justify-content: center; flex-direction: column; align-items: center; gap: 10px;">
            <div>
              <el-button size="mini" type="warning" @click="dynamicAnalysis(scope.$index, scope.row)">动态解析</el-button>
            </div>
            <div>
              <el-button size="mini" type="danger" @click="handleDelete(scope.$index, scope.row)">删  除</el-button>
            </div>
          </div>
        </template>
      </el-table-column>
    </el-table>
        </div> -->
    <el-tab-pane label="Record" name="fifth">
      <div ref="tableScroll" style="height: 450px; overflow: auto; margin-left: 50px">
        <el-table :data="tableData">
          <el-table-column label="APP" width="150px">
            <template slot-scope="scope">
              <el-popover trigger="hover" placement="top">
                <el-button type="primary" @click="getStaticReport(scope.row)">Static Report</el-button>
                <el-button type="success" @click="getDynamicReport(scope.row)">Dynamic Report</el-button>
                <div slot="reference" class="name-wrapper">
                  <el-tag size="medium">{{ scope.row.APP_NAME }}</el-tag>
                </div>
              </el-popover>
            </template>
          </el-table-column>

          <el-table-column label="分析结果" width="150">
            <template slot-scope="scope">
              <div>静态结果:{{ scope.row.STATIC }}</div>
              <div>动态结果:{{ scope.row.DYNAMIC }}</div>
            </template>
          </el-table-column>

          <el-table-column label="名单" width="120px">
            <template slot-scope="scope">
              <div>{{ scope.row.LIST }}</div>
            </template>
          </el-table-column>

          <el-table-column label="MD5" width="200px">
            <template slot-scope="scope">
              <div>{{ scope.row.MD5 }}</div>
            </template>
          </el-table-column>

          <el-table-column label="扫描日期" width="120px">
            <template slot-scope="scope">
              <div>{{ scope.row.TIMESTAMP }}</div>
            </template>
          </el-table-column>

          <el-table-column label="操作" width="120px">
            <template slot-scope="scope">
              <div style="display: flex; justify-content: center; flex-direction: column; align-items: center; gap: 10px;">
                <div>
                  <el-button size="mini" type="warning" @click="dynamicAnalysis(scope.$index, scope.row)">动态解析</el-button>
                </div>
                <div>
                  <el-button size="mini" type="danger" @click="handleDelete(scope.$index, scope.row)">删  除</el-button>
                </div>
              </div>
            </template>
          </el-table-column>
        </el-table>

        <el-pagination
          v-if="totalItems > 0"
          :current-page="currentPage"
          :page-size="pageSize"
          :total="totalItems"
          layout="total, prev, pager, next"
          @current-change="handlePageChange">
        </el-pagination>
      <!-- </div>
    </el-tab-pane> -->
  </div>
        </el-tab-pane>
        
      </el-tabs>
    </div>

    <!-- <div>footer</div> -->
  </div>
</template>

<script>
import axios from 'axios';
import { QrcodeCapture } from "vue-qrcode-reader";
import { saveAs } from 'file-saver';
import { Loading } from 'element-ui'
import { RouterView } from 'vue-router';

export default {
  name: 'HomePage',
  components: { QrcodeCapture },
  data() {
    return {
      activeName: 'first',
      apkFile: null,
      whiteList: null,
      blackList: null,
      url_input: '',
      querryInput: '',
      secretKey: process.env.VUE_APP_APIKEY,
      // 历史记录
      tableData: [{},{},{},{},{},{},{}],
      listData: [],
      dialogVisible: false,
      loading: false,
      currentPage:1,
      totalItems:3,
      pageSize:3,
      uploadApkReturnData : {}
    };
  },
  created() {
    this.getList(1); 
  },
  methods: {
    jump() {
      this.$router.push('/test');
    },
    // 识别二维码
    onDetect(detectedCodes) {
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在识别二维码，可能时间较长，请稍候...", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      detectedCodes.then(result => {
        downloadLoadingInstance.close();
        window.open(result.content);
      }).catch(error => {  
        downloadLoadingInstance.close();
        this.$message({
          message: '二维码解析失败:请确保网络畅通和二维码的清晰度!',
          type: 'warning'
        });
      });
    },
    // url下载apk
    urlDownload() {
      window.open(this.url_input);
    },

    submitAPK(file, Url) {
      
      this.loading = true;
      const formData = new FormData();
      formData.append('file', file);

      const headers = {
        'Authorization': this.secretKey,
        'Content-Type': 'multipart/form-data'
      };
        axios.post(Url, formData, { headers }).then(res=>{
        console.log(res.data)
        this.uploadApkReturnData = {
          'analyzer' : res.data.analyzer,
           'status' : res.data.status,
           'hash' : res.data.hash,
           'scan_type' : res.data.scan_type,
           'file_name' : res.data.file_name,
           'list' :res.data.list,
        }
        this.loading = false;
        this.dialogVisible = true;
      }).catch(error=>{
        this.loading = false;
        this.$message({
          message: '上传失败:'+error,
          type: 'warning'
        });
      })
    },
    apkUpload(event){
      this.apkFile = event.target.files[0];
      // submit(this.apkFile, '');
      // this.dialogVisible = true;
      this.submitAPK(this.apkFile, '/api/v1/upload');
    },
    staticAnalysis(){
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在分析，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const headers = {
        'Authorization': this.secretKey
      };
        const formData = new FormData();
        formData.append('hash', this.uploadApkReturnData.hash);
        axios.post('/api/v1/scan', formData, { headers })
         .then(res => {
          console.log(res.data);
          downloadLoadingInstance.close();
          if('error' in res.data){
            this.$message({
            message: '静态解析失败：'+ res.data.error,
            type: 'error'
          });
          }else{
            this.getList(1); 
            this.$message({
            message: '静态解析成功！请查看历史记录中的相应报告',
            type: 'success'
          });
          }
        })
        .catch(error => {
          downloadLoadingInstance.close();
          console.error('Error:', error);
          this.$message({
            message: '静态解析失败:'+error,
            type: 'error'
          });
        });
        this.dialogVisible = false;
      
    },
    submitExcel(file, Url) {
      
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在上传，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
 
      const formData = new FormData();
      formData.append('file', file);

      const headers = {
        'Authorization': this.secretKey,
        'Content-Type': 'multipart/form-data'
      };
      
        axios.post(Url, formData, { headers })
          .then(res =>{
            downloadLoadingInstance.close();
            if ('error' in  res.data){
              this.$message({
              message: '上传失败:' + res.data.error,
              type: 'error'
            });
            }
            else{
              this.$message({
              message: '上传成功！',
              type: 'success'
            });
            }
          }).catch(error =>{
            downloadLoadingInstance.close();
              this.$message({
               message: '上传失败:Excel文件缺少必要的列: packageName, apkName, md5, result',
               type: 'warning'
                });
          });
    },
    handleWhiteListUpload(event) {
      this.whiteList = event.target.files[0];
      this.submitExcel(this.whiteList, '/api/v1/import_whitelist');
    },
    handleBlackListUpload(event) {
      this.blackList = event.target.files[0];
      this.submitExcel(this.blackList, '/api/v1/import_blacklist');
    },
    // 分页查询历史记录
    async getList(page = 1) {
      this.currentPage = page
      try {
        const headers = {
          'Authorization': this.secretKey
        };
        const response = await axios.get(`/api/v1/scans?page_size=${this.pageSize}&page=${this.currentPage}`, { headers });
        this.totalItems = response.data.count;
        this.tableData = response.data.content;
      } catch (error) {
        // console.error('Error fetching list:', error);
        this.$message({
          message: '获取列表数据失败，请重试。',
          type: 'error'
        });
      }
    },
    handlePageChange(page) {
      this.getList(page);
    },
    // handleScroll(event) {  
    //     const target = event.target;  
    //     const scrollDistance = target.scrollHeight - target.scrollTop - target.clientHeight;  
  
    //     if (scrollDistance < 3) { // 接近底部10px时加载数据  
    //         this.getList();  
    //     }  
    // },
    handleScrollList(event) {  
        const target = event.target;  
        const scrollDistance = target.scrollHeight - target.scrollTop - target.clientHeight;  
  
        if (scrollDistance < 5) { // 接近底部10px时加载数据 
          //懒得写了 
        }  
    },
    getStaticReport(row) {
      let downloadLoadingInstance;
      downloadLoadingInstance = Loading.service({ text: "正在生成报告，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const formData = new FormData();
      formData.append('hash', row.MD5);
      axios.post('/api/v1/download_pdf', formData , {
        headers: {
          'Authorization': process.env.VUE_APP_APIKEY,
          'Content-Type': 'application/x-www-form-urlencoded' 
        },
        responseType: 'blob' // 确保服务器返回的内容作为 Blob 处理
      })
      .then(response => {
        downloadLoadingInstance.close();
        const blob = new Blob([response.data], { type: 'application/pdf' });
        saveAs(blob, '静态报告.pdf'); // 使用 saveAs 保存文件
      })
      .catch(error => {
        downloadLoadingInstance.close();
        this.$message({
          message: '生成失败:未找到报告',
          type: 'error'
        });
      });

    },
    getDynamicReport(row) {
      const formData = new FormData();
      formData.append('hash', row.MD5);
      axios.post('/api/v1/dynamic/download_txt', formData, {
        headers: {
          'Authorization': process.env.VUE_APP_APIKEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        responseType: 'blob' // 确保服务器返回的内容作为 Blob 处理
      })
      .then(response => {
        const blob = new Blob([response.data], { type: 'text/plain' });
        saveAs(blob, '动态报告.txt'); // 使用 saveAs 保存文件
      })
      .catch(error => {
        console.error('错误!', error);
        this.$message({
          message: '未找到报告，请先动态分析',
          type: 'error'
        });
      });
   },
    dynamicAnalysis(index, row){
      let md5 = row.MD5
      this.$router.push(`/dynamicAnalysis/${md5}`);
    },
    handleDelete(index, row) {
      let downloadLoadingInstance;
    downloadLoadingInstance = Loading.service({ text: "正在删除，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
      const formData = new FormData();
      formData.append('hash', row.MD5);

      axios.post('/api/v1/delete_scan', formData, {
        headers: {
          'Authorization': process.env.VUE_APP_APIKEY,
        }
      })
      .then(response => {
        downloadLoadingInstance.close();
        this.tableData.splice(index, 1);
        this.$message({
          message: `删除了 ${row.APP_NAME}`,
          type: 'success'
        });
      })
      .catch(error => {
        downloadLoadingInstance.close();
        console.error('错误!', error);
        this.$message({
          message: '删除失败',
          type: 'error'
        });
      });
    },
    querryList() {
    let select_list = this.querryInput.split(/:|：/);
    if (select_list.length > 1 && select_list[1] != null) {
      let condition_list = select_list[1].split('&');
      const formData = new FormData();
      for (let i = 0; i < condition_list.length; i++) {
        let condition = condition_list[i].split('=');
        if (condition.length === 2) {
          formData.append(condition[0], condition[1]);
        } else {
          this.$message({
            message: '条件格式不正确，请使用 key=value 形式',
            type: 'error'
          });
        }
      }
      if (select_list[0] === '白名单') {
        this.getWhite(formData);
      } else if (select_list[0] === '黑名单') {
        this.getBlack(formData);
      } else {
        this.$message({
          message: '请按照格式: 白名单:MD5=111&Result=black&PackageName=1231&App=12',
          type: 'error'
        });
      }
    } else {
      this.$message({
        message: '请至少添加一个条件',
        type: 'error'
      });
    }
  },
  getWhite(formData) {
    let downloadLoadingInstance;
    downloadLoadingInstance = Loading.service({ text: "正在查询，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
    axios.post('/api/v1/get_whitelist', formData, {
      headers: {
        'Authorization': process.env.VUE_APP_APIKEY,
      }
    })
    .then(response => {
      downloadLoadingInstance.close();
      console.log(response);
      this.listData = response.data;
      this.$message({
        message: '查询成功',
        type: 'success'
      });
    })
    .catch(error => {
      downloadLoadingInstance.close();
      console.error('错误!', error);
      this.$message({
        message: '查询失败' + error,
        type: 'error'
      });
    });
  },
  getBlack(formData) {
    let downloadLoadingInstance;
    downloadLoadingInstance = Loading.service({ text: "正在查询，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
    axios.post('/api/v1/get_blacklist', formData, {
      headers: {
        'Authorization': process.env.VUE_APP_APIKEY,
      }
    })
    .then(response => {
      downloadLoadingInstance.close();
      console.log(response.data);
      this.listData = response.data;
      this.$message({
        message: '查询成功',
        type: 'success'
      });
    })
    .catch(error => {
      downloadLoadingInstance.close();
      console.error('错误!', error);
      this.$message({
        message: '查询失败: ' + error,
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
  // color: white;
  // // position: absolute;
  // // top: 0;
  // // left: 0;
  // // right: 0;
  // // padding: 1rem 5rem;

  // display: flex;
  // justify-content: space-between;
  // align-items: center;
  // z-index: 200;
  // .menu-bar {
  //   display: flex;
  //   gap: 3rem
  // }
  // .menu-bar li {
  //     list-style: none;
  // }
  // .menu-bar li a {
  //     color: white;
  //     text-decoration: none;
  //     padding-bottom: 4px;
  //     font-size: 18px;
  //     border-bottom: 2px solid transparent;
  //     transition: all 0.3s ease;
  // }
  // .menu-bar li a:hover {

  //     border-bottom: 2px solid white;
  // }
}

.my-main {
  // height: 500px;
  width: 1900px;
  height: 520px;
  max-width: 1000px;
  min-width: 1000px;
  max-height: 520px;
  min-height: 520px;
  position: absolute;
  // top: 25; /* 向上移动自身高度的50% */  
  left: 440px; /* 向左移动自身宽度的50% */  
  margin-top: 150px;
  // transform: translate(-50%, -50%); /* 通过transform调整位置，使其真正居中 */
  background-color: #FFFFFF;
  border-radius: 10px;
  box-shadow: 0 0 2px rgba(0, 0, 0, 0.5);
  padding: 20px;
  .tab {
    width: 1000px;
    height: 520px;
    max-width: 1000px;
    min-width: 1000px;
    max-height: 520px;
    min-height: 520px;
    margin: 0 auto;
    .inner {
      margin-top: 70px;
      .el-row {
        margin-bottom: 30px;
        &:last-child {
          margin-bottom: 0;
        }
      }
    }
  }
}
.qrcode_container{
  margin-left: 5px;
  margin-top: 70px;
  position: relative;
  width: 988px;
  height: 200px;
  border: 1px dashed #505050;
}
.hidden-but-clickable {  
  //position: absolute; /* 或者使用 fixed，取决于你的需求 */  
  // top: -9999px; /* 将元素移出视口 */  
  // left: -9999px; /* 将元素移出视口 */  
  /* 可以添加其他样式以确保元素不影响页面布局 */
  position: absolute;  
  top: 0;  
  left: 0; 
  width: 988px; /* 根据需要设置宽度 */  
  height: 200px; /* 根据需要设置高度 */  
  /* 你可以保持透明度为1，或者设置为0，取决于你的需求 */  
  opacity: 0; /* 如果你想让元素完全透明但仍然可点击，可以设置为0 */  
  cursor: pointer; /* 显示鼠标悬停时为点击状态 */  
} 
form img{
  display: none;
  max-width: 988px;
}
form .content i{
  margin-top: 50px;
  color: #354BD8;
  font-size: 55px;
}
form .content p{
  color: #354BD8;
  margin-top: 15px;
  font-size: 16px;
}
.apk_container{
  input[type="file"] {
  display: none;
  
}
.apklabel {
    display: block;
    position: relative;
    // background-color: #025bee;
    // color: #ffffff;
    background-color: #EAEDFB;
    color: #364DD6;
    border: 0.5px solid #354BD8;
    border-color: #354BD8;
    // font-size: 1.12em;
    // font-weight: 500;
    text-align: center;
    width: 8vw;
    // height: 0.2vh;
    // padding: 1.12em 0;
    padding: 0.46em 0;
    margin: auto;
    border-radius: 0.31em;
    cursor: pointer;
  }
  .apklabel:hover {
    background-color: #354BD8;
    color: white;

  }
}
.wbButtonContainer{
  input[type="file"] {
  display: none;
  }
  .wbLabel-w {
    display: block;
    position: relative;
    background-color: #F26D6D;
    color: white;
    border: 0.5px solid #F26D6D;
    border-color: #F26D6D;
    text-align: center;
    width: 200px;
    padding: 0.46em 0;
    border-radius: 0.31em;
    cursor: pointer;
  }
  .wbLabel-w:hover {
    background-color: #F48A8A;
    color: white;

  }
  .wbLabel-b {
    display: block;
    position: relative;
    background-color: #68C241;
    color: white;
    border: 0.5px solid #68C241;
    border-color: #68C241;
    text-align: center;
    width: 200px;
    padding: 0.46em 0;
    border-radius: 0.31em;
    cursor: pointer;
  }
  .wbLabel-b:hover {
    background-color: #86CE65;
    color: white;

  }
}
.tag{
  margin-right: 1vw;
  width: 4vw;
}
</style>
