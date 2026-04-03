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
                <h2 class="text-base font-medium text-white">Overview</h2>
                <p class="text-sm text-gray-500">monitor and manage running processes</p>
              </div>
              
              <div class="flex items-center space-x-4">
                <!-- Auto-refresh Toggle Button -->
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
                
                <!-- Refresh Button -->
                <button
                  @click="refreshData"
                  :disabled="isLoading"
                  class="border border-gray-500/10 text-sm rounded-xl px-4 py-2 text-white bg-gray-500/10 hover:bg-gray-500/15 flex items-center space-x-2"
                >
                  <ArrowPathIcon 
                    :class="['w-4 h-4', isLoading ? 'animate-spin' : '']" 
                  />
                  <span>{{ isLoading ? 'Refreshing...' : 'Refresh' }}</span>
                </button>
                
              </div>
            </div>
          </div>
        </header>

        <!-- Main Content -->
        <main class="flex-1 overflow-y-auto">
          <!-- Stats Overview -->
          <div class="grid grid-cols-1 md:grid-cols-5 gap-6 border-b border-gray-500/10 p-6">
            <StatsCard
              title="Total Processes"
              :value="processes.length"
              :change="processChange"
              :icon="BeakerIcon"
              color="blue"
            />
            <StatsCard
              title="Active Ports"
              :value="activePorts"
              :change="portChange"
              :icon="GlobeAltIcon"
              color="green"
            />
            <StatsCard
              title="Docker Containers"
              :value="dockerContainers"
              :change="0"
              :icon="CubeIcon"
              color="purple"
            />
            <StatsCard
              title="Port Conflicts"
              :value="conflictCount"
              :change="0"
              :icon="ExclamationTriangleIcon"
              color="orange"
            />
            <StatsCard
              title="System Load"
              :value="systemLoad"
              :change="0"
              :icon="ChartBarIcon"
              color="yellow"
            />
          </div>

          <!-- System Resources -->
          <SystemResources ref="systemResourcesRef" />

          <!-- Process Table -->
          <div class="overflow-auto">
            <div class="px-6 py-4 border-b border-gray-500/10">
              <div class="flex justify-between items-center">
                <h2 class="text-xs font-medium uppercase text-gray-500">
                  Running Processes
                </h2>
                <div class="flex space-x-2">
                  <button
                    @click="killAllProcesses"
                    :disabled="processes.length === 0 || isLoading"
                    class="border border-gray-500/10 rounded-xl text-sm px-4 py-2 text-white bg-gray-500/10 hover:bg-gray-500/15 flex items-center space-x-2"
                  >
                    <XMarkIcon class="w-4 h-4" />
                    <span>Kill All</span>
                  </button>
                  <NuxtLink
                    to="/processes"
                    class="border border-gray-500/10 rounded-xl text-sm px-3 py-2 text-gray-400 bg-transparent hover:bg-gray-500/15 flex items-center space-x-2"
                  >
                    <EyeIcon class="w-4 h-4" />
                    <span>View All</span>
                  </NuxtLink>
                </div>
              </div>
            </div>

            <div class="flex flex-col sm:flex-row gap-4 p-6 py-4">
              <div class="flex-1">
                <!-- <label for="search" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Search Processes
                </label> -->
                <div class="relative">
                  <MagnifyingGlassIcon class="absolute left-4 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    id="search"
                    v-model="searchQuery"
                    type="text"
                    placeholder="Search by process name, port, or PID..."
                    class="w-full pl-12 pr-4 py-3 text-sm placeholder:text-gray-500 bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30"
                  />
                </div>
              </div>
              
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
              :processes="limitedProcesses"
              :is-loading="isLoading"
              :has-port-conflict="hasPortConflict"
              @kill-process="killProcess"
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
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { 
  ArrowPathIcon, 
  MagnifyingGlassIcon,
  XMarkIcon,
  ExclamationTriangleIcon,
  PlayIcon,
  PauseIcon,
  GlobeAltIcon,
  CubeIcon,
  ChartBarIcon,
  ChevronDownIcon,
  BeakerIcon,
  EyeIcon
} from '@heroicons/vue/24/solid'

// Meta data for SEO and social sharing
useHead({
  title: 'Overview',
})


// Components
import StatsCard from '~/components/StatsCard.vue'
import ProcessTable from '~/components/ProcessTable.vue'
import SettingsModal from '~/components/SettingsModal.vue'
import SystemResources from '~/components/SystemResources.vue'
import Sidebar from '~/components/Sidebar.vue'

// Reactive data
const processes = ref([])
const isLoading = ref(false)
const isConnected = ref(false)
const searchQuery = ref('')
const selectedPortRange = ref('all')
const customPortStart = ref('')
const customPortEnd = ref('')
const statusFilter = ref('all')
const showSettings = ref(false)
const isAutoRefreshEnabled = ref(true)
const systemResourcesRef = ref(null)
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

// Helper function to detect port conflicts
const hasPortConflict = (process) => {
  // Get all processes using the same port
  const processesOnSamePort = processes.value.filter(p => p.port === process.port)
  
  if (processesOnSamePort.length <= 1) {
    return false
  }
  
  // Simple conflict detection: if there are multiple processes on the same port
  // and at least one is a Docker process (com.docke) and one is not (like node),
  // then it's a conflict
  const hasDockerProcess = processesOnSamePort.some(p => p.command === 'com.docke')
  const hasNonDockerProcess = processesOnSamePort.some(p => p.command !== 'com.docke')
  
  return hasDockerProcess && hasNonDockerProcess
}

// Computed properties
const filteredProcesses = computed(() => {
  let filtered = processes.value

  // Search filter
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(process => 
      process.name.toLowerCase().includes(query) ||
      process.command.toLowerCase().includes(query) ||
      process.port.toString().includes(query) ||
      process.pid.toString().includes(query) ||
      (process.container_name && process.container_name.toLowerCase().includes(query))
    )
  }

  // Port range filter
  if (selectedPortRange.value !== 'all') {
    if (selectedPortRange.value === 'custom') {
      // Handle custom range input
      if (customPortStart.value && customPortEnd.value) {
        const start = parseInt(customPortStart.value)
        const end = parseInt(customPortEnd.value)
        if (!isNaN(start) && !isNaN(end) && start <= end) {
          filtered = filtered.filter(process => process.port >= start && process.port <= end)
        }
      }
    } else {
      const [start, end] = selectedPortRange.value.split('-').map(Number)
      filtered = filtered.filter(process => process.port >= start && process.port <= end)
    }
  }

  // Status filter
  if (statusFilter.value !== 'all') {
    if (statusFilter.value === 'docker') {
      // Show only Docker-related processes (containers, Docker daemon, etc.)
      filtered = filtered.filter(process => 
        process.container_id || 
        process.command.includes('docker') || 
        process.name.includes('docker') ||
        process.command.includes('com.docke')
      )
    } else if (statusFilter.value === 'running') {
      // Show only host processes (non-Docker, non-container)
      filtered = filtered.filter(process => 
        (process.container_id === 'host-process' || !process.container_id) && 
        !process.command.includes('docker') && 
        !process.command.includes('com.docke')
      )
    } else if (statusFilter.value === 'stopped') {
      // Show only processes that are not actively running
      // This is a bit tricky since we're monitoring active processes
      // For now, we'll show processes with very low CPU usage or specific states
      filtered = filtered.filter(process => 
        process.status === 'stopped' || 
        process.status === 'sleeping' ||
        process.status === 'idle'
      )
    } else if (statusFilter.value === 'conflicts') {
      // Show only processes involved in port conflicts
      filtered = filtered.filter(process => hasPortConflict(process))
    }
  }

  return filtered
})

// Show only first 10 on overview page
const limitedProcesses = computed(() => filteredProcesses.value.slice(0, 10))

const activePorts = computed(() => {
  return new Set(processes.value.map(p => p.port)).size
})

const conflictCount = computed(() => {
  return processes.value.filter(process => hasPortConflict(process)).length
})

const dockerContainers = computed(() => {
  // Count Docker-related processes (containers and daemon processes)
  return processes.value.filter(p => 
    p.container_id === 'docker-daemon' || 
    (p.container_id && 
     p.container_id !== 'host-process' &&
     p.container_name &&
     p.container_name !== 'Host Process')
  ).length
})

const systemLoad = computed(() => {
  // This would be calculated from system metrics
  return 'Normal'
})

const processChange = ref(0)
const portChange = ref(0)

// Use useLazyFetch for data fetching
const { data: processesData, error: processesError, pending: processesPending, refresh: refreshProcesses } = await useLazyFetch('/api/processes', {
  server: true, // Fetch on server side first
  default: () => ({ processes: [] }),
  immediate: true, // Ensure immediate fetch
  query: {
    ports: '2000-9000',
    docker: true,
    verbose: true,
    performance: true,
    showContext: true,
    smartFilter: false,
    remoteMode: false,
    remoteHost: ''
  }
})

// Watch for data changes and update local state
watch(processesData, (newData) => {
  if (newData && newData.processes) {
    const previousCount = processes.value.length
    processes.value = newData.processes
    processChange.value = processes.value.length - previousCount
    isConnected.value = true
  }
}, { immediate: true })

// Watch for errors
watch(processesError, (newError) => {
  if (newError) {
    console.error('Failed to fetch processes:', newError)
    isConnected.value = false
  }
})

// Watch for loading state
watch(processesPending, (isPending) => {
  isLoading.value = isPending
})

// Methods
const refreshData = async (showLoading = true) => {
  try {
    if (showLoading) {
      isLoading.value = true
    }
    const newData = await $fetch('/api/processes', {
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
    if (newData && newData.success) {
      processes.value = newData.processes
      isConnected.value = true
    }
    
    // Also refresh system resources (non-blocking)
    nextTick(() => {
      try {
        if (systemResourcesRef.value && typeof systemResourcesRef.value.refreshData === 'function') {
          systemResourcesRef.value.refreshData()
        }
      } catch (error) {
        console.warn('Failed to refresh system resources:', error)
      }
    })
  } catch (err) {
    console.error('Error refreshing processes:', err)
    isConnected.value = false
  } finally {
    if (showLoading) {
      isLoading.value = false
    }
  }
}

const killProcess = async (pid) => {
  try {
    await $fetch(`/api/processes/${pid}`, { method: 'DELETE' })
    
    // Remove the killed process from the local array immediately
    const processIndex = processes.value.findIndex(p => p.pid === pid)
    if (processIndex !== -1) {
      processes.value.splice(processIndex, 1)
      // Update the process change count
      processChange.value = -1
    }
  } catch (error) {
    console.error('Failed to kill process:', error)
    
    // Show user-friendly error message
    const errorMessage = error.data?.statusMessage || error.message || 'Failed to kill process'
    alert(`Error: ${errorMessage}`)
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
          verbose: settings.value.verbose,
          performance: true,
          showContext: true,
          smartFilter: false,
          remoteMode: settings.value.remoteMode,
          remoteHost: settings.value.remoteHost
        }
      })
      
      // Clear all processes from the local array immediately
      const previousCount = processes.value.length
      processes.value = []
      processChange.value = -previousCount
    } catch (error) {
      console.error('Failed to kill all processes:', error)
    }
  }
}

const saveSettings = (newSettings) => {
  settings.value = { ...newSettings }
  // Restart monitoring with new settings
  refreshData()
  
  // Restart auto-refresh with new interval if it's enabled
  if (isAutoRefreshEnabled.value) {
    if (refreshInterval) {
      clearInterval(refreshInterval)
    }
    refreshInterval = setInterval(() => refreshData(false), settings.value.refreshInterval)
  }
}

// Auto-refresh
let refreshInterval = null

const toggleAutoRefresh = () => {
  isAutoRefreshEnabled.value = !isAutoRefreshEnabled.value
  
  if (isAutoRefreshEnabled.value) {
    // Start auto-refresh (silent - no loading state)
    refreshInterval = setInterval(() => refreshData(false), settings.value.refreshInterval)
  } else {
    // Stop auto-refresh
    if (refreshInterval) {
      clearInterval(refreshInterval)
      refreshInterval = null
    }
  }
}

onMounted(() => {
  // Start auto-refresh on mount (silent - no loading state)
  if (isAutoRefreshEnabled.value) {
    refreshInterval = setInterval(() => refreshData(false), settings.value.refreshInterval)
  }
})

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
  }
})
</script>
