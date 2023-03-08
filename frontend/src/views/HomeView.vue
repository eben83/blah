<script setup>
import {ref} from "vue";
import axios from "axios";

const user = ref({
    userName: null,
    email: null,
    password: null
})

const registerUser = () => {
    return new Promise((resolve, reject) => {
        axios.post('https://localhost:44348/api/Authentication/register-admin', user.value)
            .then(response => {
                resolve(response)
                console.log('RESPONSE', response)
            })
            .catch((err) => {
                reject()
                console.log("ERROR", err)
            })
    })
    
}

</script>

<template>
  <main>
      register
      
      <h3>user Name</h3> 
      <input type="text" v-model="user.userName">
    
      <h3>Email</h3>
      <input type="text" v-model="user.email">
    
      <h3>Password</h3>
      <input type="text" v-model="user.password">
      
      <div>
          <button @click="registerUser">Save</button>
      </div>
  </main>
</template>
