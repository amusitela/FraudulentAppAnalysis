import axios from 'axios'
import { Notification, MessageBox, Message, Loading } from 'element-ui'
import { tansParams, blobValidate } from "@/utils/tools";
import { saveAs } from 'file-saver'

let downloadLoadingInstance;

axios.defaults.headers['Content-Type'] = 'application/json;charset=utf-8'
// 创建axios实例
const service = axios.create({

  baseURL : '/backend',
  headers: { 'Access-Control-Allow-Origin': '*' },
  // 超时
  timeout: 2137483647,
})
// 通用下载方法
export function download_file(url, params, filename, config) {
  downloadLoadingInstance = Loading.service({ text: "正在下载文件，请稍候", spinner: "el-icon-loading", background: "rgba(0, 0, 0, 0.7)", })
  return service.post(url, params, {
    transformRequest: [(params) => {console.log(tansParams(params)); return tansParams(params) }],
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    responseType: 'blob',
    ...config
  }).then(async (data) => {
    const isBlob = blobValidate(data);
    if (isBlob) {
      const blob = new Blob([data])
      saveAs(blob, filename)
    } else {
      const resText = await data.text();
      const rspObj = JSON.parse(resText);
     
    }
    downloadLoadingInstance.close();
  }).catch((r) => {
    console.error(r)
    Message.error('下载文件出现错误！')
    downloadLoadingInstance.close();
  })
}

export default service