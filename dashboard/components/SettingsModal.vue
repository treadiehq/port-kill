<template>
  <div v-if="open" class="fixed inset-0 z-50 overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
      <!-- Background overlay -->
      <div 
        class="fixed inset-0 bg-black bg-opacity-75 transition-opacity"
        @click="$emit('update:open', false)"
      ></div>

      <!-- Modal panel -->
      <div class="inline-block align-bottom bg-[#0b0b10] border border-gray-500/10 rounded-xl text-left overflow-hidden transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
        <div class="">
          <div class="sm:flex sm:items-start">
            <!-- <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 dark:bg-blue-900 sm:mx-0 sm:h-10 sm:w-10">
              <Cog6ToothIcon class="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div> -->
            <div class="text-center sm:text-left w-full">
              <h3 class="text-lg leading-6 font-medium text-white border-b border-gray-500/10 px-4 py-4">
                Settings
              </h3>
              <div class="space-y-4 px-4 py-4">
                <!-- Port Range -->
                <div>
                  <label for="ports" class="block text-sm font-medium text-white">
                    Port Range
                  </label>
                  <input
                    id="ports"
                    v-model="localConfig.ports"
                    type="text"
                    placeholder="2000-9000"
                    class="mt-2 block w-full px-4 py-3 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30"
                  />
                  <p class="mt-1 text-xs text-gray-500">
                    Port range to monitor (e.g., 2000-9000 or specific ports: 3000,8000,8080)
                  </p>
                </div>

                <!-- Ignore Ports -->
                <div>
                  <label for="ignorePorts" class="block text-sm font-medium text-white">
                    Ignore Ports
                  </label>
                  <input
                    id="ignorePorts"
                    v-model="localConfig.ignorePorts"
                    type="text"
                    placeholder="5353"
                    class="mt-2 block w-full px-4 py-3 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30"
                  />
                  <p class="mt-1 text-xs text-gray-500">
                    Comma-separated list of ports to ignore (e.g., Chromecast, AirDrop)
                  </p>
                </div>

                <!-- Ignore Processes -->
                <div>
                  <label for="ignoreProcesses" class="block text-sm font-medium text-white">
                    Ignore Processes
                  </label>
                  <input
                    id="ignoreProcesses"
                    v-model="localConfig.ignoreProcesses"
                    type="text"
                    placeholder="Chrome,ControlCe,rapportd"
                    class="mt-2 block w-full px-4 py-3 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30"
                  />
                  <p class="mt-1 text-xs text-gray-500">
                    Comma-separated list of process names to ignore
                  </p>
                </div>

                <!-- Docker Support -->
                <div class="flex items-center space-x-3">
                  <div class="relative">
                    <input
                      id="docker"
                      v-model="localConfig.docker"
                      type="checkbox"
                      class="sr-only"
                    />
                    <label
                      for="docker"
                      class="flex items-center justify-center w-5 h-5 bg-gray-500/10 border-2 border-gray-500/10 rounded-md cursor-pointer transition-all duration-200 hover:border-gray-500/10 hover:bg-gray-500/10"
                      :class="{
                        '!bg-blue-300 border-blue-300 hover:bg-blue-300 hover:border-blue-300': localConfig.docker,
                        'hover:shadow-lg hover:shadow-blue-500/10': localConfig.docker
                      }"
                    >
                      <svg
                        v-if="localConfig.docker"
                        class="w-3 h-3 text-white"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fill-rule="evenodd"
                          d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                          clip-rule="evenodd"
                        />
                      </svg>
                    </label>
                  </div>
                  <label for="docker" class="text-sm text-white cursor-pointer select-none">
                    Enable Docker container monitoring
                  </label>
                </div>

                <!-- Verbose Mode -->
                <div class="flex items-center space-x-3">
                  <div class="relative">
                    <input
                      id="verbose"
                      v-model="localConfig.verbose"
                      type="checkbox"
                      class="sr-only"
                    />
                    <label
                      for="verbose"
                      class="flex items-center justify-center w-5 h-5 bg-gray-500/10 border-2 border-gray-500/10 rounded-md cursor-pointer transition-all duration-200 hover:border-gray-500/10 hover:bg-gray-500/10"
                      :class="{
                        '!bg-blue-300 border-blue-300 hover:bg-blue-300 hover:border-blue-300': localConfig.verbose,
                        'hover:shadow-lg hover:shadow-blue-500/10': localConfig.verbose
                      }"
                    >
                      <svg
                        v-if="localConfig.verbose"
                        class="w-3 h-3 text-white"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fill-rule="evenodd"
                          d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                          clip-rule="evenodd"
                        />
                      </svg>
                    </label>
                  </div>
                  <label for="verbose" class="text-sm text-white cursor-pointer select-none">
                    Enable verbose mode (show command line and working directory)
                  </label>
                </div>

                <!-- Remote Mode -->
                <div class="flex items-center space-x-3">
                  <div class="relative">
                    <input
                      id="remoteMode"
                      v-model="localConfig.remoteMode"
                      type="checkbox"
                      class="sr-only"
                    />
                    <label
                      for="remoteMode"
                      class="flex items-center justify-center w-5 h-5 bg-gray-500/10 border-2 border-gray-500/10 rounded-md cursor-pointer transition-all duration-200 hover:border-gray-500/10 hover:bg-gray-500/10"
                      :class="{
                        '!bg-blue-300 border-blue-300 hover:bg-blue-300 hover:border-blue-300': localConfig.remoteMode,
                        'hover:shadow-lg hover:shadow-blue-500/10': localConfig.remoteMode
                      }"
                    >
                      <svg
                        v-if="localConfig.remoteMode"
                        class="w-3 h-3 text-white"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fill-rule="evenodd"
                          d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                          clip-rule="evenodd"
                        />
                      </svg>
                    </label>
                  </div>
                  <label for="remoteMode" class="text-sm text-white cursor-pointer select-none">
                    Remote Mode (SSH)
                  </label>
                </div>

                <!-- Remote Host (shown when remote mode is enabled) -->
                <div v-if="localConfig.remoteMode">
                  <label for="remoteHost" class="block text-sm font-medium text-white">
                    Remote Host
                  </label>
                  <input
                    id="remoteHost"
                    v-model="localConfig.remoteHost"
                    type="text"
                    placeholder="user@server.com"
                    class="mt-2 block w-full px-4 py-3 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30"
                  />
                  <p class="mt-1 text-xs text-gray-500">
                    SSH connection string (e.g., user@staging.company.com)
                  </p>
                </div>

                <!-- Refresh Interval -->
                <div>
                  <label for="refreshInterval" class="block text-sm font-medium text-white">
                    Refresh Interval
                  </label>
                  <div class="relative mt-2">
                    <select
                      id="refreshInterval"
                      v-model="localConfig.refreshInterval"
                      class="appearance-none w-full px-4 py-3 text-sm bg-transparent border border-gray-500/10 rounded-xl text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 outline-none transition-all duration-200 hover:border-gray-500/30 cursor-pointer"
                    >
                      <option :value="2000" class="bg-gray-800 text-white">2 seconds</option>
                      <option :value="5000" class="bg-gray-800 text-white">5 seconds</option>
                      <option :value="10000" class="bg-gray-800 text-white">10 seconds</option>
                      <option :value="30000" class="bg-gray-800 text-white">30 seconds</option>
                    </select>
                    <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                      <ChevronDownIcon class="w-4 h-4 text-gray-400" />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="border-t border-gray-500/10 px-4 py-3 sm:px-4 sm:py-4 sm:flex sm:flex-row-reverse">
          <button
            @click="saveSettings"
            class="w-full inline-flex justify-center rounded-xl border border-transparent shadow-sm px-4 py-2 bg-blue-300 text-base font-medium text-black hover:bg-blue-400 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-300 sm:ml-3 sm:w-auto sm:text-sm"
          >
            Save
          </button>
          <button
            @click="$emit('update:open', false)"
            class="mt-3 w-full inline-flex justify-center rounded-xl border border-gray-500/10 shadow-sm px-4 py-2 bg-gray-500/5 text-base font-medium text-white hover:bg-gray-500/10 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500/10 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { Cog6ToothIcon, ChevronDownIcon } from '@heroicons/vue/24/outline'

const props = defineProps({
  open: {
    type: Boolean,
    default: false
  },
  config: {
    type: Object,
    required: true
  }
})

const emit = defineEmits(['update:open', 'save'])

const localConfig = ref({ ...props.config })

watch(() => props.config, (newConfig) => {
  localConfig.value = { ...newConfig }
}, { deep: true })

const saveSettings = () => {
  emit('save', { ...localConfig.value })
  emit('update:open', false)
}
</script>
