<template>
  <div>
    <form @submit.prevent="submitForm">
      <div>
        <label for="file">选择文件:</label>
        <input type="file" @change="handleFileUpload" id="file">
      </div>
      <button type="submit">上传</button>
    </form>
    <div v-if="response">
      <h3>Response:</h3>
      <pre>{{ response }}</pre>
    </div>
  </div>
</template>
<script>
import axios from 'axios';

export default {
  data() {
    return {
      file: null,
      response: null,
      secretKey: 'a789e65653ed5e42560fcdd3b8a2c772afa666d9d39aeb42352753faa9f81728',  // 写成配置文件形式的
      Url: '/api/v1/upload'  
    };
  },
  methods: {
    handleFileUpload(event) {
      this.file = event.target.files[0];
    },
    async submitForm() {
      if (!this.file) {
        alert("请选择一个文件");
        return;
      }

      const formData = new FormData();
      formData.append('file', this.file, this.file.name);

      const headers = {
        'Authorization': this.secretKey,
        'Content-Type': 'multipart/form-data'
      };

      try {
        const res = await axios.post(this.Url, formData, { headers });
        this.response = res.data;
      } catch (error) {
        console.error('Error:', error);
        this.response = error.response ? error.response.data : '上传失败';
      }
    }
  }
};
</script>
<style scoped>
/* 添加一些基本样式 */
form div {
  margin-bottom: 10px;
}
button {
  padding: 5px 10px;
}
</style>
