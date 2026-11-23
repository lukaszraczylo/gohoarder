import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { configureStrictMode } from '@perfect-design/ui'
import router from './router'
import App from './App.vue'
import './styles/main.css'

configureStrictMode(import.meta.env.DEV ? 'throw' : 'warn')

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.mount('#app')
