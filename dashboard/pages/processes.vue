<template>
  <div class="h-screen bg-black flex">
    <!-- Left Sidebar -->
    <Sidebar :is-connected="isConnected" :remote-mode="settings.remoteMode" :remote-host="settings.remoteHost" @open-settings="showSettings = true" />

    <!-- Main Content Area -->
    <div class="flex-1 flex flex-col mr-2 my-2 rounded-xl bg-gray-500/10 border border-gray-500/10 overflow-hidden">
      <!-- Top Header -->
      <header class="border-b border-gray-500/10">
        <div class="px-6 py-3">
          <div class="flex justify-between items-center">
            <div class="flex items-center space-x-2">
              <h2 class="text-base font-medium text-white">Running Processes</h2>
              <p class="text-sm text-gray-500">monitor and manage ports</p>
            </div>
            <div class="flex items-center space-x-2">
              <button
                @click="toggleAutoRefresh"
                :class="[
                  'flex items-center space-x-2 px-3 py-2 text-sm rounded-xl transition-colors duration-200',
                  isAutoRefreshEnabled 
                    ? 'bg-transparent text-gray-400 border border-gray-500/10 hover:bg-gray-500/15' 
                    : 'bg-orange-400/10 text-orange-400 hover:bg-orange-400/15'
                ]"
                :title="isAutoRefreshEnabled ? 'Pause auto-refresh' : 'Resume auto-refresh'"
              >
                <PlayIcon v-if="!isAutoRefreshEnabled" class="w-4 h-4" />
                <PauseIcon v-else class="w-4 h-4" />
                <span>{{ isAutoRefreshEnabled ? 'Pause' : 'Resume' }}</span>
              </button>
              <button 
                @click="refreshData(true)" 
                :disabled="isLoading"
                class="border border-gray-500/10 text-sm rounded-xl px-4 py-2 text-white bg-gray-500/10 hover:bg-gray-500/15 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
              >
                <ArrowPathIcon :class="['w-4 h-4', isLoading ? 'animate-spin' : '']" />
                <span>{{ isLoading ? 'Refreshing...' : 'Refresh' }}</span>
              </button>
							<span class="text-sm text-gray-500/10">|</span>
              <button
                @click="killAllProcesses"
                :disabled="processes.length === 0 || isLoading"
                class="border border-gray-500/10 text-sm rounded-xl px-4 py-2 text-white bg-gray-500/10 hover:bg-gray-500/15 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
                title="Kill all detected processes"
              >
                <XMarkIcon class="w-4 h-4" />
                <span>Kill All</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <!-- Content -->
      <main class="flex-1 overflow-y-auto">
        <div class="">
          <!-- Search and Filters -->
          <div class="flex flex-col sm:flex-row gap-4 px-6 py-4">
            <!-- Search -->
            <div class="flex-1">
              <div class="relative">
                <MagnifyingGlassIcon class="absolute left-4 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  id="search-processes"
                  v-model="searchQuery"
                  type="text"
                  placeholder="Search by process name, port, or PID..."
                  class="w-full pl-12 pr-4 py-3 text-sm placeholder:text-gray-500 bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30"
                />
              </div>
            </div>

            <!-- Port Filter -->
            <div class="sm:w-48">
              <div class="relative">
                <select
                  id="port-filter"
                  v-model="selectedPortRange"
                  class="appearance-none w-full px-4 py-3 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30 cursor-pointer"
                >
                  <option value="all" class="bg-gray-800 text-white">All Ports</option>
                  <option value="3000-4000" class="bg-gray-800 text-white">3000-4000</option>
                  <option value="4000-5000" class="bg-gray-800 text-white">4000-5000</option>
                  <option value="5000-6000" class="bg-gray-800 text-white">5000-6000</option>
                  <option value="custom" class="bg-gray-800 text-white">Custom Range</option>
                </select>
                <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                  <ChevronDownIcon class="w-4 h-4 text-gray-400" />
                </div>
              </div>
              
              <!-- Custom Range Input -->
              <div v-if="selectedPortRange === 'custom'" class="mt-2">
                <div class="flex items-center space-x-2">
                  <input
                    v-model="customPortStart"
                    type="number"
                    placeholder="Start"
                    class="w-full px-3 py-2 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white placeholder:text-gray-500 focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none"
                    min="1"
                    max="65535"
                  />
                  <span class="text-gray-400">-</span>
                  <input
                    v-model="customPortEnd"
                    type="number"
                    placeholder="End"
                    class="w-full px-3 py-2 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white placeholder:text-gray-500 focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none"
                    min="1"
                    max="65535"
                  />
                </div>
              </div>
            </div>

            <!-- Status Filter -->
            <div class="sm:w-48">
              <div class="relative">
                <select
                  id="status-filter"
                  v-model="statusFilter"
                  class="appearance-none w-full px-4 py-3 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30 cursor-pointer"
                >
                  <option value="all" class="bg-gray-800 text-white">All Status</option>
                  <option value="running" class="bg-gray-800 text-white">Running</option>
                  <option value="stopped" class="bg-gray-800 text-white">Stopped</option>
                  <option value="docker" class="bg-gray-800 text-white">Docker</option>
                  <option value="conflicts" class="bg-gray-800 text-white">Port Conflicts</option>
                </select>
                <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                  <ChevronDownIcon class="w-4 h-4 text-gray-400" />
                </div>
              </div>
            </div>
          </div>

          <ProcessTable
            :processes="filteredProcesses"
            :is-loading="isLoading"
            :has-port-conflict="hasPortConflict"
            @kill-process="onKillProcess"
          />
        </div>
      </main>
    </div>
    
    <!-- Settings Modal -->
    <SettingsModal
      v-model:open="showSettings"
      :config="settings"
      @save="saveSettings"
    />
  </div>
  
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ArrowPathIcon, PlayIcon, PauseIcon, XMarkIcon, MagnifyingGlassIcon, ChevronDownIcon } from '@heroicons/vue/24/solid'
import ProcessTable from '@/components/ProcessTable.vue'
import Sidebar from '@/components/Sidebar.vue'
import SettingsModal from '@/components/SettingsModal.vue'

// State
const processes = ref([])
const isLoading = ref(false)
let timer = null
const isConnected = ref(false)
const isAutoRefreshEnabled = ref(true)

// Settings
const settings = ref({
  ports: '2000-9000',
  ignorePorts: '5353',
  ignoreProcesses: '',
  docker: true,
  verbose: true,
  refreshInterval: 10000,
  remoteMode: false,
  remoteHost: ''
})
const showSettings = ref(false)

// Helpers
const hasPortConflict = (proc) => {
  if (!proc || !proc.port) return false
  return processes.value.filter(p => p.port === proc.port).length > 1
}

// Filters
const searchQuery = ref('')
const selectedPortRange = ref('all')
const customPortStart = ref('')
const customPortEnd = ref('')
const statusFilter = ref('all')

const filteredProcesses = computed(() => {
  let filtered = processes.value
  // search
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    filtered = filtered.filter(p =>
      p.name?.toLowerCase().includes(q) ||
      p.command?.toLowerCase().includes(q) ||
      String(p.port).includes(q) ||
      String(p.pid).includes(q) ||
      p.container_name?.toLowerCase().includes(q)
    )
  }
  // port range
  if (selectedPortRange.value !== 'all') {
    if (selectedPortRange.value === 'custom') {
      if (customPortStart.value && customPortEnd.value) {
        const s = parseInt(customPortStart.value)
        const e = parseInt(customPortEnd.value)
        if (!isNaN(s) && !isNaN(e) && s <= e) {
          filtered = filtered.filter(p => p.port >= s && p.port <= e)
        }
      }
    } else {
      const [s, e] = selectedPortRange.value.split('-').map(Number)
      filtered = filtered.filter(p => p.port >= s && p.port <= e)
    }
  }
  // status
  if (statusFilter.value !== 'all') {
    if (statusFilter.value === 'docker') {
      filtered = filtered.filter(p => p.container_id || p.command?.includes('docker') || p.command?.includes('com.docke'))
    } else if (statusFilter.value === 'running') {
      filtered = filtered.filter(p => (p.container_id === 'host-process' || !p.container_id) && !p.command?.includes('docker') && !p.command?.includes('com.docke'))
    } else if (statusFilter.value === 'conflicts') {
      filtered = filtered.filter(p => hasPortConflict(p))
    }
  }
  return filtered
})

// Data actions
const refreshData = async (showLoading = true) => {
  try {
    if (showLoading) isLoading.value = true
    
    const data = await $fetch('/api/processes', {
      query: {
        ports: settings.value.ports,
        ignorePorts: settings.value.ignorePorts,
        ignoreProcesses: settings.value.ignoreProcesses,
        docker: settings.value.docker,
        verbose: settings.value.verbose,
        performance: true,
        showContext: true,
        smartFilter: false,
        remoteMode: settings.value.remoteMode,
        remoteHost: settings.value.remoteHost
      }
    })
    
    if (data && data.success) {
      processes.value = data.processes || []
      isConnected.value = true
    } else {
      isConnected.value = false
    }
  } catch (e) {
    console.error('Failed to refresh processes:', e)
    isConnected.value = false
  } finally {
    if (showLoading) isLoading.value = false
  }
}

const onKillProcess = async (process) => {
  try {
    const pid = typeof process === 'object' ? process.pid : process
    await $fetch(`/api/processes/${pid}`, { method: 'DELETE' })
    const idx = processes.value.findIndex(p => p.pid === pid)
    if (idx !== -1) processes.value.splice(idx, 1)
  } catch (e) {
    console.error('Failed to kill process:', e)
    const msg = e?.data?.statusMessage || e.message || 'Failed to kill process'
    alert(`Error: ${msg}`)
  }
}

const killAllProcesses = async () => {
  if (confirm('Are you sure you want to kill all processes?')) {
    try {
      await $fetch('/api/processes/kill-all', {
        method: 'POST',
        query: {
          ports: settings.value.ports,
          ignorePorts: settings.value.ignorePorts,
          ignoreProcesses: settings.value.ignoreProcesses,
          docker: settings.value.docker,
          performance: true,
          showContext: true,
          smartFilter: false,
          verbose: settings.value.verbose,
          remoteMode: settings.value.remoteMode,
          remoteHost: settings.value.remoteHost
        }
      })
      const previousCount = processes.value.length
      processes.value = []
      // Optionally you can show feedback or compute delta
      console.log(`Killed ${previousCount} processes`)
    } catch (e) {
      console.error('Failed to kill all processes:', e)
      const msg = e?.data?.statusMessage || e.message || 'Failed to kill all processes'
      alert(`Error: ${msg}`)
    }
  }
}

const saveSettings = (newSettings) => {
  settings.value = { ...newSettings }
  // Restart monitoring with new settings
  refreshData()
  
  // Restart auto-refresh with new interval if it's enabled
  if (isAutoRefreshEnabled.value) {
    if (timer) {
      clearInterval(timer)
    }
    timer = setInterval(() => refreshData(false), settings.value.refreshInterval)
  }
}

// Lifecycle
onMounted(async () => {
  await refreshData(true) // Show loading state on initial load
  if (isAutoRefreshEnabled.value) {
    timer = setInterval(() => refreshData(false), settings.value.refreshInterval)
  }
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})

const toggleAutoRefresh = () => {
  isAutoRefreshEnabled.value = !isAutoRefreshEnabled.value
  if (isAutoRefreshEnabled.value) {
    // start
    if (timer) clearInterval(timer)
    timer = setInterval(() => refreshData(false), settings.value.refreshInterval)
  } else {
    // stop
    if (timer) clearInterval(timer)
    timer = null
  }
}
// Meta
useHead({
  title: 'Running Processes',
  meta: [
    { name: 'description', content: 'Track and view running processes' }
  ]
})
</script>


