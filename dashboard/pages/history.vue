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
              <h2 class="text-base font-medium text-white">Process History & Analytics</h2>
              <p class="text-sm text-gray-500">track killed processes and analyze patterns</p>
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
                class="border border-gray-500/10 text-sm rounded-xl px-4 py-2 text-white bg-gray-500/10 hover:bg-gray-500/15 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
              >
                <ArrowPathIcon 
                  :class="['w-4 h-4', isLoading ? 'animate-spin' : '']" 
                />
                <span>{{ isLoading ? 'Refreshing...' : 'Refresh' }}</span>
              </button>

              <span class="text-sm text-gray-500/10">|</span>

              <!-- Clear Button -->
              <button
                @click="clearHistory"
                :disabled="isLoading"
                class="flex items-center space-x-2 px-3 py-2 text-sm rounded-xl border border-gray-500/10 text-white bg-gray-500/10 hover:bg-gray-500/15 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <TrashIcon class="w-4 h-4" />
                <span>Clear</span>
              </button>
              
            </div>
          </div>
        </div>
      </header>

      <!-- Analytics Tabs -->
      <div class="border-b border-gray-500/10">
        <nav class="flex space-x-8 px-6">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            @click="activeTab = tab.id"
            :class="[
              'py-3 px-1 border-b-2 text-sm transition-colors duration-200',
              activeTab === tab.id
                ? 'border-blue-300 text-blue-300'
                : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
            ]"
          >
            {{ tab.name }}
          </button>
        </nav>
      </div>

      <!-- Main Content -->
      <main class="flex-1 overflow-y-auto">
        <div class="">
          <!-- History Tab -->
          <div v-if="activeTab === 'history'">
            <ProcessHistory 
              ref="processHistoryRef"
              :auto-refresh="isAutoRefreshEnabled"
              @refresh="refreshData"
              @clear="refreshData"
            />
          </div>

          <!-- Statistics Tab -->
          <div v-if="activeTab === 'stats'" class="">
            <!-- Main Statistics Cards -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 p-6">
              <!-- Total Kills Card -->
              <div class="group relative rounded-xl p-6 border border-gray-500/10 bg-gray-500/5 transition-all duration-300">
                <div class="flex items-center justify-between mb-4">
                  <div class="p-3 bg-red-500/10 rounded-xl">
                    <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                    </svg>
                  </div>
                  <div class="text-right">
                    <div class="text-3xl font-bold text-white group-hover:text-red-400 transition-colors">{{ stats?.total_kills || 0 }}</div>
                    <div class="text-sm text-gray-400 font-medium">Total Kills</div>
                  </div>
                </div>
                <div class="text-xs text-gray-500">Processes terminated</div>
              </div>

              <!-- Unique Processes Card -->
              <div class="group relative rounded-xl p-6 border border-gray-500/10 bg-gray-500/5 transition-all duration-300">
                <div class="flex items-center justify-between mb-4">
                  <div class="p-3 bg-blue-300/10 rounded-xl">
                    <svg class="w-6 h-6 text-blue-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path>
                    </svg>
                  </div>
                  <div class="text-right">
                    <div class="text-3xl font-bold text-white group-hover:text-blue-300 transition-colors">{{ stats?.unique_processes || 0 }}</div>
                    <div class="text-sm text-gray-400 font-medium">Unique Processes</div>
                  </div>
                </div>
                <div class="text-xs text-gray-500">Different process types</div>
              </div>

              <!-- Unique Ports Card -->
              <div class="group relative rounded-xl p-6 border border-gray-500/10 bg-gray-500/5 transition-all duration-300">
                <div class="flex items-center justify-between mb-4">
                  <div class="p-3 bg-green-400/10 rounded-xl">
                    <svg class="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path>
                    </svg>
                  </div>
                  <div class="text-right">
                    <div class="text-3xl font-bold text-white group-hover:text-green-400 transition-colors">{{ stats?.unique_ports || 0 }}</div>
                    <div class="text-sm text-gray-400 font-medium">Unique Ports</div>
                  </div>
                </div>
                <div class="text-xs text-gray-500">Different port numbers</div>
              </div>

              <!-- Average Kills/Day Card -->
              <div class="group relative rounded-xl p-6 border border-gray-500/10 bg-gray-500/5 transition-all duration-300">
                <div class="flex items-center justify-between mb-4">
                  <div class="p-3 bg-purple-400/10 rounded-xl">
                    <svg class="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                    </svg>
                  </div>
                  <div class="text-right">
                    <div class="text-3xl font-bold text-white group-hover:text-purple-400 transition-colors">{{ stats?.average_kills_per_day?.toFixed(1) || '0.0' }}</div>
                    <div class="text-sm text-gray-400 font-medium">Avg Kills/Day</div>
                  </div>
                </div>
                <div class="text-xs text-gray-500">Daily average</div>
              </div>
            </div>

            <!-- Detailed Statistics Cards -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 border-t border-gray-500/10 p-6">
              <!-- Most Killed Card -->
              <div class="rounded-xl p-6 border border-gray-500/10 transition-all duration-300">
                <div class="flex items-center mb-6">
                  <div class="p-2 bg-orange-400/10 rounded-xl mr-4">
                    <svg class="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                    </svg>
                  </div>
                  <h3 class="text-base font-semibold text-white">Top Rankings</h3>
                </div>
                <div class="space-y-4">
                  <!-- Top Processes -->
                  <div v-if="stats?.top_processes && stats.top_processes.length > 0" class="">
                    <h4 class="text-xs font-medium uppercase text-gray-500 mb-2">Processes</h4>
                    <div class="space-y-2">
                      <div 
                        v-for="(process, index) in stats.top_processes" 
                        :key="index"
                        class="flex items-center justify-between p-3 bg-gray-500/5 rounded-xl border border-gray-500/10"
                      >
                        <div class="flex items-center">
                          <div class="w-6 h-6 bg-orange-400/10 rounded-full flex items-center justify-center mr-3">
                            <span class="text-orange-400 text-xs font-bold">{{ index + 1 }}</span>
                          </div>
                          <span class="text-gray-300 font-medium">{{ process[0] }}</span>
                        </div>
                        <div class="text-right">
                          <div class="text-orange-400 text-sm font-semibold">{{ process[1] }} times</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <!-- Top Ports -->
                  <div v-if="stats?.top_ports && stats.top_ports.length > 0" class="">
                    <h4 class="text-xs font-medium uppercase text-gray-500 mb-2">Ports</h4>
                    <div class="space-y-2">
                      <div 
                        v-for="(port, index) in stats.top_ports" 
                        :key="index"
                        class="flex items-center justify-between p-3 bg-gray-500/5 rounded-xl border border-gray-500/10"
                      >
                        <div class="flex items-center">
                          <div class="w-6 h-6 bg-blue-300/10 rounded-full flex items-center justify-center mr-3">
                            <span class="text-blue-300 text-xs font-bold">{{ index + 1 }}</span>
                          </div>
                          <span class="text-gray-300 font-medium">Port {{ port[0] }}</span>
                        </div>
                        <div class="text-right">
                          <div class="text-blue-300 text-sm font-semibold">{{ port[1] }} times</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <!-- Top Projects -->
                  <div v-if="stats?.top_projects && stats.top_projects.length > 0" class="">
                    <h4 class="text-xs font-medium uppercase text-gray-500 mb-2">Projects</h4>
                    <div class="space-y-2">
                      <div 
                        v-for="(project, index) in stats.top_projects" 
                        :key="index"
                        class="flex items-center justify-between p-3 bg-gray-500/5 rounded-xl border border-gray-500/10"
                      >
                        <div class="flex items-center">
                          <div class="w-6 h-6 bg-green-400/10 rounded-full flex items-center justify-center mr-3">
                            <span class="text-green-400 text-xs font-bold">{{ index + 1 }}</span>
                          </div>
                          <span class="text-gray-300 font-medium">{{ project[0] }}</span>
                        </div>
                        <div class="text-right">
                          <div class="text-green-400 text-sm font-semibold">{{ project[1] }} times</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Time Range Card -->
              <div class="rounded-xl p-6 border border-gray-500/10 transition-all duration-300">
                <div class="flex items-center mb-6">
                  <div class="p-2 bg-indigo-400/10 rounded-xl mr-4">
                    <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                  </div>
                  <h3 class="text-base font-semibold text-white">Time Range</h3>
                </div>
                <div class="space-y-2">
                  <div v-if="stats?.oldest_kill" class="flex items-center justify-between p-3 bg-gray-500/5 rounded-xl border border-gray-500/10">
                    <div class="flex items-center">
                      <div class="w-2 h-2 bg-indigo-400 rounded-full mr-3"></div>
                      <span class="text-gray-300 font-medium">Oldest Kill</span>
                    </div>
                    <div class="text-right">
                      <div class="text-white font-semibold">{{ formatDate(stats.oldest_kill) }}</div>
                      <div class="text-indigo-400 text-sm">First recorded</div>
                    </div>
                  </div>
                  <div v-if="stats?.newest_kill" class="flex items-center justify-between p-3 bg-gray-500/5 rounded-xl border border-gray-500/10">
                    <div class="flex items-center">
                      <div class="w-2 h-2 bg-purple-400 rounded-full mr-3"></div>
                      <span class="text-gray-300 font-medium">Newest Kill</span>
                    </div>
                    <div class="text-right">
                      <div class="text-white font-semibold">{{ formatDate(stats.newest_kill) }}</div>
                      <div class="text-purple-400 text-sm">Most recent</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Frequent Offenders Tab -->
          <div v-if="activeTab === 'offenders'" class="space-y-4">
            <div v-if="offenders.length === 0" class="text-center py-12">
              <div class="text-gray-400 text-lg">No frequent offenders found</div>
              <div class="text-gray-500 text-sm mt-2">Processes that are killed multiple times will appear here</div>
            </div>
            <div v-else class="divide-y divide-gray-500/10">
              <div 
                v-for="(offender, index) in offenders" 
                :key="index"
                class="p-6"
              >
                <div class="flex justify-between items-start">
                  <div>
                    <div class="text-lg font-medium text-white">{{ offender.process_name }}</div>
                    <div class="text-sm text-gray-400">Port {{ offender.port }}</div>
                    <div v-if="offender.process_group" class="text-sm text-orange-400 mt-1">
                      Group: {{ offender.process_group }}
                    </div>
                    <div v-if="offender.project_name" class="text-sm text-blue-300 mt-1">
                      Project: {{ offender.project_name }}
                    </div>
                  </div>
                  <div class="text-right">
                    <div class="text-2xl font-bold text-red-400">{{ offender.kill_count }}</div>
                    <div class="text-sm text-gray-400">kills</div>
                  </div>
                </div>
                <div class="mt-3 pt-3 border-t border-gray-500/10">
                  <div class="flex justify-between uppercase text-xs text-gray-500">
                    <span>First: {{ formatDate(offender.first_killed) }}</span>
                    <span>Last: {{ formatDate(offender.last_killed) }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Suggestions Tab -->
          <div v-if="activeTab === 'suggestions'" class="space-y-4">
            <div v-if="!suggestions || (suggestions.suggested_ports.length === 0 && suggestions.suggested_processes.length === 0 && suggestions.suggested_groups.length === 0)" class="text-center py-12">
              <div class="text-gray-400 text-lg">No suggestions available</div>
              <div class="text-gray-500 text-sm mt-2">Your current ignore settings are working well!</div>
            </div>
            <div v-else class="divide-y divide-gray-500/10">
              <!-- Suggested Ports -->
              <div v-if="suggestions.suggested_ports.length > 0" class="p-6">
                <h3 class="font-medium mb-4 uppercase text-xs text-gray-500">Ports to Ignore</h3>
                <div class="space-y-2">
                  <div v-for="port in suggestions.suggested_ports" :key="port" class="flex items-center justify-between">
                    <span class="text-gray-300">Port {{ port }}</span>
                    <code class="bg-gray-500/10 px-2 py-1 rounded-xl text-sm text-orange-400">--ignore-ports {{ port }}</code>
                  </div>
                </div>
              </div>

              <!-- Suggested Processes -->
              <div v-if="suggestions.suggested_processes.length > 0" class="p-6">
                <h3 class="font-medium mb-4 uppercase text-xs text-gray-500">Process Names to Ignore</h3>
                <div class="space-y-2">
                  <div v-for="process in suggestions.suggested_processes" :key="process" class="flex items-center justify-between">
                    <span class="text-gray-300">{{ process }}</span>
                    <code class="bg-gray-500/10 px-2 py-1 rounded-xl text-sm text-orange-400">--ignore-processes {{ process }}</code>
                  </div>
                </div>
              </div>

              <!-- Suggested Groups -->
              <div v-if="suggestions.suggested_groups.length > 0" class="p-6">
                <h3 class="font-medium mb-4 uppercase text-xs text-gray-500">Groups to Ignore</h3>
                <div class="space-y-2">
                  <div v-for="group in suggestions.suggested_groups" :key="group" class="flex items-center justify-between">
                    <span class="text-gray-300">{{ group }}</span>
                    <code class="bg-gray-500/10 px-2 py-1 rounded-xl text-sm text-orange-400">--ignore-groups {{ group }}</code>
                  </div>
                </div>
              </div>

              <!-- Complete Command Example -->
              <div class="p-6">
                <h3 class="font-medium mb-4 uppercase text-xs text-gray-500">Command Example</h3>
                <div class="bg-gray-500/10 rounded-xl p-4">
                  <code class="text-orange-400 text-sm">
                    ./port-kill-console --console --ports 3000,8000
                    <span v-if="suggestions.suggested_ports.length > 0"> --ignore-ports {{ suggestions.suggested_ports.join(',') }}</span>
                    <span v-if="suggestions.suggested_processes.length > 0"> --ignore-processes {{ suggestions.suggested_processes.join(',') }}</span>
                    <span v-if="suggestions.suggested_groups.length > 0"> --ignore-groups {{ suggestions.suggested_groups.join(',') }}</span>
                  </code>
                </div>
              </div>
            </div>
          </div>

          <!-- Smart Root Cause Tab -->
          <div v-if="activeTab === 'root-cause'" class="space-y-6">
            <div v-if="!rootCauseAnalysis" class="text-center py-12">
              <div class="text-gray-400 text-lg">Loading root cause analysis...</div>
              <div class="text-gray-500 text-sm mt-2">Analyzing your process history for patterns and conflicts</div>
            </div>
            <div v-else class="divide-y divide-gray-500/10">
              <!-- Analysis Summary -->
              <div class="p-6">
                <div class="flex items-center mb-4">
                  <div class="p-2 bg-blue-300/10 rounded-xl mr-4">
                    <svg class="w-5 h-5 text-blue-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path>
                    </svg>
                  </div>
                  <h3 class="text-xl font-semibold text-white">Summary</h3>
                </div>
                <p class="text-gray-300">{{ rootCauseAnalysis.summary }}</p>
                <div class="mt-4 text-sm text-gray-400">
                  {{ formatDate(rootCauseAnalysis.analysis_timestamp) }}
                </div>
              </div>

              <!-- Conflicts Section -->
              <div v-if="rootCauseAnalysis.conflicts && rootCauseAnalysis.conflicts.length > 0" class="space-y-4 p-6">
                <h3 class="text-xs font-semibold uppercase text-gray-500 flex items-center">
                  <!-- <div class="p-2 bg-blue-300/10 rounded-xl mr-4">
                    <svg class="w-5 h-5 text-red-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                    </svg>
                  </div> -->
                  Detected Conflicts
                </h3>
                <div class="grid gap-4">
                  <div 
                    v-for="(conflict, index) in rootCauseAnalysis.conflicts" 
                    :key="index"
                    class="bg-gray-500/5 rounded-xl p-4 border border-gray-500/10"
                  >
                    <div class="flex items-center justify-between mb-3">
                      <div class="flex items-center">
                        <div class="w-8 h-8 bg-gray-500/10 rounded-full flex items-center justify-center mr-3">
                          <span class="text-gray-400 text-sm font-bold">{{ index + 1 }}</span>
                        </div>
                        <div>
                          <div class="text-white font-semibold">Port {{ conflict.port }}</div>
                          <div class="text-sm text-gray-400">{{ formatConflictType(conflict.conflict_type) }}</div>
                        </div>
                      </div>
                      <div class="text-right">
                        <div :class="getSeverityColor(conflict.severity)" class="text-sm font-medium">
                          {{ formatSeverity(conflict.severity) }}
                        </div>
                      </div>
                    </div>
                    <div class="mb-3">
                      <div class="text-[10px] font-medium text-gray-500 uppercase mb-1">Conflicting Processes:</div>
                      <div class="flex flex-wrap gap-2">
                        <span 
                          v-for="process in conflict.conflicting_processes" 
                          :key="process"
                          class="bg-gray-500/5 border border-gray-500/10 px-2 py-1 rounded-xl text-sm text-gray-300"
                        >
                          {{ process }}
                        </span>
                      </div>
                    </div>
                    <div class="text-xs text-gray-300 bg-gray-500/5 border border-gray-500/10 p-3 rounded-xl">
                      <strong>Recommendation:</strong> {{ conflict.recommendation }}
                    </div>
                  </div>
                </div>
              </div>

              <!-- Patterns Section -->
              <div v-if="rootCauseAnalysis.patterns && rootCauseAnalysis.patterns.length > 0" class="space-y-4 p-6">
                <h3 class="text-xs font-semibold uppercase text-gray-500 flex items-center">
                  <!-- <svg class="w-5 h-5 text-yellow-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                  </svg> -->
                  Workflow Patterns
                </h3>
                <div class="grid gap-4">
                  <div 
                    v-for="(pattern, index) in rootCauseAnalysis.patterns" 
                    :key="index"
                    class="bg-gray-500/5 rounded-xl p-4 border border-gray-500/10"
                  >
                    <div class="flex items-center justify-between mb-3">
                      <div class="flex items-center">
                        <div class="w-8 h-8 bg-gray-500/10 rounded-full flex items-center justify-center mr-3">
                          <span class="text-gray-400 text-sm font-bold">{{ index + 1 }}</span>
                        </div>
                        <div>
                          <div class="text-white font-semibold">{{ pattern.description }}</div>
                          <div class="text-sm text-gray-400">{{ formatPatternType(pattern.pattern_type) }}</div>
                        </div>
                      </div>
                      <div class="text-right">
                        <div class="text-yellow-400 text-sm font-medium">
                          {{ Math.round(pattern.confidence * 100) }}% confidence
                        </div>
                      </div>
                    </div>
                    <div class="mb-3">
                      <div class="text-[10px] font-medium text-gray-500 uppercase mb-1">Frequency:</div>
                      <div class="text-gray-300">{{ pattern.frequency }}</div>
                    </div>
                    <div class="text-xs text-gray-300 bg-gray-500/5 border border-gray-500/10 p-3 rounded-xl">
                      <strong>Recommendation:</strong> {{ pattern.recommendation }}
                    </div>
                  </div>
                </div>
              </div>

              <!-- Recommendations Section -->
              <div v-if="rootCauseAnalysis.recommendations && rootCauseAnalysis.recommendations.length > 0" class="space-y-4 p-6">
                <h3 class="text-xs font-semibold uppercase text-gray-500 flex items-center">
                  <!-- <svg class="w-5 h-5 text-green-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path>
                  </svg> -->
                  Smart Recommendations
                </h3>
                <div class="grid gap-4">
                  <div 
                    v-for="(rec, index) in rootCauseAnalysis.recommendations" 
                    :key="index"
                    class="bg-gray-500/5 rounded-xl p-4 border border-gray-500/10"
                  >
                    <div class="flex items-center justify-between mb-3">
                      <div class="flex items-center">
                        <div class="w-8 h-8 bg-gray-500/10 rounded-full flex items-center justify-center mr-3">
                          <span class="text-gray-400 text-sm font-bold">{{ index + 1 }}</span>
                        </div>
                        <div>
                          <div class="text-white font-semibold">{{ rec.title }}</div>
                          <div class="text-sm text-gray-400">{{ formatCategory(rec.category) }}</div>
                        </div>
                      </div>
                      <div class="text-right">
                        <div :class="getPriorityColor(rec.priority)" class="text-sm font-medium">
                          {{ formatPriority(rec.priority) }}
                        </div>
                      </div>
                    </div>
                    <div class="mb-3">
                      <div class="text-[10px] font-medium text-gray-500 uppercase mb-1">Description:</div>
                      <div class="text-gray-300">{{ rec.description }}</div>
                    </div>
                    <div class="mb-3">
                      <div class="text-[10px] font-medium text-gray-500 uppercase mb-1">Action:</div>
                      <div class="text-gray-300">{{ rec.action }}</div>
                    </div>
                    <div class="text-xs text-gray-300 bg-gray-500/5 border border-gray-500/10 p-3 rounded-xl">
                      <strong>Impact:</strong> {{ rec.impact }}
                    </div>
                  </div>
                </div>
              </div>

              <!-- No Issues State -->
              <div v-if="(!rootCauseAnalysis.conflicts || rootCauseAnalysis.conflicts.length === 0) && 
                        (!rootCauseAnalysis.patterns || rootCauseAnalysis.patterns.length === 0) && 
                        (!rootCauseAnalysis.recommendations || rootCauseAnalysis.recommendations.length === 0)" 
                   class="text-center py-12">
                <div class="text-green-400 text-lg">No issues detected!</div>
                <div class="text-gray-500 text-sm mt-2">Your development workflow is running smoothly</div>
              </div>
            </div>
          </div>

          <!-- Port Guard Tab -->
          <div v-if="activeTab === 'port-guard'" class="space-y-6">
            <div v-if="!portGuardStatus" class="text-center py-12">
              <div class="text-gray-400 text-lg">Loading Port Guard status...</div>
              <div class="text-gray-500 text-sm mt-2">Checking guard daemon status</div>
            </div>
            <div v-else class="divide-y divide-gray-500/10">
              <!-- Guard Status Overview -->
              <div class="p-6">
                <div class="flex items-center justify-between mb-4">
                  <div class="flex items-center">
                    <div class="p-3 bg-green-500/10 rounded-xl mr-4">
                      <svg class="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                      </svg>
                    </div>
                    <div>
                      <h3 class="text-xl font-semibold text-white">Port Guard Status</h3>
                      <div class="flex items-center mt-1">
                        <div :class="portGuardStatus.is_active ? 'bg-green-400' : 'bg-red-500'" class="w-2 h-2 rounded-full mr-2"></div>
                        <span class="text-sm text-gray-400">
                          {{ portGuardStatus.is_active ? 'Active' : 'Inactive' }}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div class="text-right">
                    <div class="text-2xl font-bold text-white">{{ portGuardStatus.conflicts_resolved }}</div>
                    <div class="text-sm text-gray-400">Conflicts Resolved</div>
                  </div>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                  <div class="bg-gray-500/5 border border-gray-500/10 rounded-xl p-4">
                    <div class="text-sm text-gray-400 mb-1">Watched Ports</div>
                    <div class="text-white font-semibold">{{ portGuardStatus.watched_ports.length }}</div>
                    <div class="text-xs text-gray-500 mt-1">{{ portGuardStatus.watched_ports.join(', ') }}</div>
                  </div>
                  <div class="bg-gray-500/5 border border-gray-500/10 rounded-xl p-4">
                    <div class="text-sm text-gray-400 mb-1">Active Reservations</div>
                    <div class="text-white font-semibold">{{ portGuardStatus.active_reservations.length }}</div>
                    <div class="text-xs text-gray-500 mt-1">Port reservations</div>
                  </div>
                  <div class="bg-gray-500/5 border border-gray-500/10 rounded-xl p-4">
                    <div class="text-sm text-gray-400 mb-1">Auto Resolve</div>
                    <div class="text-white font-semibold">{{ portGuardStatus.auto_resolve_enabled ? 'Enabled' : 'Disabled' }}</div>
                    <div class="text-xs text-gray-500 mt-1">Automatic conflict resolution</div>
                  </div>
                </div>
              </div>

              <!-- Watched Ports -->
              <!-- <div v-if="portGuardStatus.watched_ports && portGuardStatus.watched_ports.length > 0" class="space-y-4 p-6">
                <h3 class="text-lg font-semibold text-white flex items-center">
                  <svg class="w-5 h-5 text-blue-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                  </svg>
                  Watched Ports
                </h3>
                <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                  <div 
                    v-for="port in portGuardStatus.watched_ports" 
                    :key="port"
                    class="bg-gray-500/10 rounded-xl p-3 text-center border border-gray-500/10"
                  >
                    <div class="text-white font-semibold">{{ port }}</div>
                    <div class="text-xs text-gray-400 mt-1">Port</div>
                  </div>
                </div>
              </div> -->

              <!-- Active Reservations -->
              <div v-if="portGuardStatus.active_reservations && portGuardStatus.active_reservations.length > 0" class="space-y-4 p-6">
                <h3 class="text-xs font-semibold uppercase text-gray-500 flex items-center">
                  <!-- <svg class="w-5 h-5 text-purple-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                  </svg> -->
                  Active Reservations
                </h3>
                <div class="grid gap-4">
                  <div 
                    v-for="reservation in portGuardStatus.active_reservations" 
                    :key="reservation.port"
                    class="bg-gray-500/5 rounded-xl p-4 border border-gray-500/10"
                  >
                    <div class="flex items-center justify-between">
                      <div class="flex items-center">
                        <div class="bg-purple-400/10 rounded-xl p-2 flex items-center justify-center mr-3">
                          <span class="text-purple-400 text-sm font-bold">{{ reservation.port }}</span>
                        </div>
                        <div>
                          <div class="text-white font-semibold">{{ reservation.project_name }}</div>
                          <div class="text-sm text-gray-400">{{ reservation.process_name }}</div>
                        </div>
                      </div>
                      <div class="text-right">
                        <div class="text-sm text-gray-400">Reserved</div>
                        <div class="text-white text-sm">{{ formatDate(reservation.reserved_at) }}</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>


              <!-- Guard Inactive State -->
              <div v-if="!portGuardStatus.is_active" class="text-center py-12">
                <div class="text-orange-400 text-lg">⚠️ Port Guard is not active</div>
                <div class="text-gray-500 text-sm mt-2">Start the guard daemon to enable proactive port conflict prevention</div>
                <div class="mt-4">
                  <code class="bg-gray-500/10 px-3 py-2 rounded-xl text-sm text-orange-400">
                    ./port-kill-console --guard-mode --auto-resolve
                  </code>
                </div>
              </div>
            </div>
          </div>

          <!-- Security Audit Tab -->
          <div v-if="activeTab === 'security-audit'" class="space-y-6">
            <div v-if="!securityAuditResult" class="text-center py-12">
              <div class="text-gray-400 text-lg">Loading Security Audit...</div>
              <div class="text-gray-500 text-sm mt-2">Analyzing system security posture</div>
            </div>
            <div v-else class="divide-y divide-gray-500/10">
              <!-- Security Audit Overview -->
              <div class="p-6">
                <div class="flex items-center justify-between mb-4">
                  <div class="flex items-center">
                    <div class="p-3 bg-red-500/10 rounded-xl mr-4">
                      <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                      </svg>
                    </div>
                    <div>
                      <h3 class="text-xl font-semibold text-white">Security Audit Results</h3>
                      <div class="flex items-center mt-1">
                        <div class="text-sm text-gray-400">
                          {{ new Date(securityAuditResult.audit_timestamp).toLocaleString() }}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="text-right">
                    <div class="text-2xl font-bold text-white">{{ securityAuditResult.security_score.toFixed(1) }}</div>
                    <div class="text-sm text-gray-400">Security Score</div>
                  </div>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                  <div class="bg-gray-500/5 border border-gray-500/10 rounded-xl p-4">
                    <div class="text-sm text-gray-400 mb-1">Total Ports Scanned</div>
                    <div class="text-white font-semibold">{{ securityAuditResult.total_ports_scanned }}</div>
                    <div class="text-xs text-gray-500 mt-1">Network endpoints analyzed</div>
                  </div>
                  <div class="bg-gray-500/5 border border-gray-500/10 rounded-xl p-4">
                    <div class="text-sm text-gray-400 mb-1">Suspicious Processes</div>
                    <div class="text-white font-semibold">{{ securityAuditResult.suspicious_processes.length }}</div>
                    <div class="text-xs text-gray-500 mt-1">Potential security risks</div>
                  </div>
                  <div class="bg-gray-500/5 border border-gray-500/10 rounded-xl p-4">
                    <div class="text-sm text-gray-400 mb-1">Approved Services</div>
                    <div class="text-white font-semibold">{{ securityAuditResult.approved_processes.length }}</div>
                    <div class="text-xs text-gray-500 mt-1">Legitimate processes</div>
                  </div>
                </div>
              </div>

              <!-- Suspicious Processes -->
              <div v-if="securityAuditResult.suspicious_processes.length > 0" class="space-y-4 p-6">
                <h3 class="text-xs font-semibold uppercase text-gray-500 flex items-center">
                  Suspicious Activity Detected
                </h3>
                <div class="grid gap-4">
                  <div 
                    v-for="(suspicious, index) in securityAuditResult.suspicious_processes" 
                    :key="suspicious.port"
                    class="bg-gray-500/5 rounded-xl p-4 border border-gray-500/10"
                  >
                    <div class="flex items-center justify-between">
                      <div class="flex items-center">
                        <div class="bg-red-500/10 rounded-xl p-2 flex items-center justify-center mr-3">
                          <span class="text-red-400 text-sm font-bold">{{ suspicious.port }}</span>
                        </div>
                        <div>
                          <div class="text-white font-semibold">{{ suspicious.process_info.name }}</div>
                          <div class="text-sm text-gray-400">PID: {{ suspicious.process_info.pid }}</div>
                          <div class="text-xs text-red-400 mt-1">
                            Risk: {{ suspicious.risk_level }} | Reason: {{ suspicious.suspicion_reason }}
                          </div>
                        </div>
                      </div>
                      <div class="text-right">
                        <div class="text-sm text-gray-400">Binary Hash</div>
                        <div class="text-white text-sm font-mono">{{ suspicious.binary_hash || 'N/A' }}</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Approved Processes -->
              <div v-if="securityAuditResult.approved_processes.length > 0" class="space-y-4 p-6">
                <h3 class="text-xs font-semibold uppercase text-gray-500 flex items-center">
                  Approved Services
                </h3>
                <div class="grid gap-4">
                  <div 
                    v-for="approved in securityAuditResult.approved_processes" 
                    :key="approved.port"
                    class="bg-gray-500/5 rounded-xl p-4 border border-gray-500/10"
                  >
                    <div class="flex items-center justify-between">
                      <div class="flex items-center">
                        <div class="bg-green-500/10 rounded-xl p-2 flex items-center justify-center mr-3">
                          <span class="text-green-400 text-sm font-bold">{{ approved.port }}</span>
                        </div>
                        <div>
                          <div class="text-white font-semibold">{{ approved.process_info.name }}</div>
                          <div class="text-sm text-gray-400">{{ approved.service_type }}</div>
                        </div>
                      </div>
                      <div class="text-right">
                        <div class="text-sm text-gray-400">Expected Location</div>
                        <div class="text-white text-sm">{{ approved.expected_location }}</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Security Recommendations -->
              <div v-if="securityAuditResult.recommendations.length > 0" class="space-y-4 p-6">
                <h3 class="text-xs font-semibold uppercase text-gray-500 flex items-center">
                  Security Recommendations
                </h3>
                <div class="grid gap-4">
                  <div 
                    v-for="(rec, index) in securityAuditResult.recommendations" 
                    :key="index"
                    class="bg-gray-500/5 rounded-xl p-4 border border-gray-500/10"
                  >
                    <div class="flex items-start justify-between">
                      <div class="flex-1">
                        <div class="text-white font-semibold">{{ rec.title }}</div>
                        <div class="text-sm text-gray-400 mt-1">{{ rec.description }}</div>
                        <div class="text-sm text-yellow-400 mt-2">Action: {{ rec.action }}</div>
                      </div>
                      <div class="ml-4">
                        <span :class="{
                          'bg-red-500/10 text-red-400': rec.priority === 'Critical',
                          'bg-orange-500/10 text-orange-400': rec.priority === 'High',
                          'bg-yellow-500/10 text-yellow-400': rec.priority === 'Medium',
                          'bg-blue-300/10 text-blue-300': rec.priority === 'Low'
                        }" class="px-2 py-1 rounded-lg text-xs font-semibold">
                          {{ rec.priority }}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- No Issues State -->
              <div v-if="securityAuditResult.suspicious_processes.length === 0" class="text-center py-12">
                <div class="text-green-400 text-lg">No suspicious processes detected!</div>
                <div class="text-gray-500 text-sm mt-2">Your system appears to be secure</div>
              </div>
            </div>
          </div>
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
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { ArrowPathIcon, PlayIcon, PauseIcon, TrashIcon } from '@heroicons/vue/24/solid'
import Sidebar from '@/components/Sidebar.vue'
import ProcessHistory from '@/components/ProcessHistory.vue'
import SettingsModal from '@/components/SettingsModal.vue'

// State
const isConnected = ref(true)
const isLoading = ref(false)
const isAutoRefreshEnabled = ref(true)
const processHistoryRef = ref(null)

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

// Analytics state
const activeTab = ref('history')
const stats = ref(null)
const offenders = ref([])
const suggestions = ref(null)
const rootCauseAnalysis = ref(null)
const portGuardStatus = ref(null)
const securityAuditResult = ref(null)

// Tabs configuration
const tabs = [
  { id: 'history', name: 'History' },
  { id: 'stats', name: 'Statistics' },
  { id: 'offenders', name: 'Frequent Offenders' },
  // { id: 'suggestions', name: 'Suggestions' },
  // { id: 'root-cause', name: 'Smart Root Cause' },
  { id: 'port-guard', name: 'Port Guard' },
  // { id: 'security-audit', name: 'Security Audit' }
]

// Auto-refresh interval
let refreshInterval = null

// Methods
const toggleAutoRefresh = () => {
  isAutoRefreshEnabled.value = !isAutoRefreshEnabled.value
  
  if (isAutoRefreshEnabled.value) {
    startAutoRefresh()
  } else {
    stopAutoRefresh()
  }
}

const startAutoRefresh = () => {
  if (refreshInterval) return
  
  refreshInterval = setInterval(() => {
    refreshData(false)
  }, settings.value.refreshInterval)
}

const stopAutoRefresh = () => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
    refreshInterval = null
  }
}

const refreshData = async (showLoading = true) => {
  try {
    if (showLoading) {
      isLoading.value = true
    }
    
    // Call the ProcessHistory component's fetchHistory method
    if (processHistoryRef.value) {
      await processHistoryRef.value.fetchHistory()
    }
    
    // Refresh analytics data when on analytics tabs
    if (activeTab.value !== 'history') {
      await refreshAnalyticsData()
    }
    
    isConnected.value = true
  } catch (error) {
    console.error('Failed to refresh data:', error)
    isConnected.value = false
  } finally {
    if (showLoading) {
      isLoading.value = false
    }
  }
}

const refreshAnalyticsData = async () => {
  try {
    // Fetch statistics
    if (activeTab.value === 'stats') {
      const statsResponse = await $fetch('/api/history/stats')
      if (statsResponse.success) {
        stats.value = statsResponse.stats
      }
    }
    
    // Fetch frequent offenders
    if (activeTab.value === 'offenders') {
      const offendersResponse = await $fetch('/api/history/offenders')
      if (offendersResponse.success) {
        offenders.value = offendersResponse.offenders
      }
    }
    
    // Fetch suggestions
    if (activeTab.value === 'suggestions') {
      const suggestionsResponse = await $fetch('/api/history/suggestions')
      if (suggestionsResponse.success) {
        suggestions.value = suggestionsResponse.suggestions
      }
    }
    
    // Fetch root cause analysis
    if (activeTab.value === 'root-cause') {
      const rootCauseResponse = await $fetch('/api/history/root-cause')
      if (rootCauseResponse.success) {
        rootCauseAnalysis.value = rootCauseResponse.analysis
      }
    }
    
    // Fetch port guard status
    if (activeTab.value === 'port-guard') {
      const guardResponse = await $fetch('/api/guard/status')
      if (guardResponse.success) {
        portGuardStatus.value = guardResponse.status
      }
    }
    
    // Fetch security audit results
    if (activeTab.value === 'security-audit') {
      const auditResponse = await $fetch('/api/security/audit')
      if (auditResponse.success) {
        securityAuditResult.value = auditResponse.data
      }
    }
  } catch (error) {
    console.error('Error fetching analytics data:', error)
  }
}

const formatDate = (dateString) => {
  if (!dateString) return 'N/A'
  const date = new Date(dateString)
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString()
}

// Helper functions for root cause analysis formatting
const formatConflictType = (type) => {
  const typeMap = {
    'PortCollision': 'Port Collision',
    'ResourceContention': 'Resource Contention',
    'AutoRestart': 'Auto Restart',
    'ParentChild': 'Parent-Child',
    'DevelopmentStack': 'Development Stack'
  }
  return typeMap[type] || type
}

const formatSeverity = (severity) => {
  const severityMap = {
    'Low': 'Low',
    'Medium': 'Medium',
    'High': 'High',
    'Critical': 'Critical'
  }
  return severityMap[severity] || severity
}

const getSeverityColor = (severity) => {
  const colorMap = {
    'Low': 'text-green-400',
    'Medium': 'text-yellow-400',
    'High': 'text-orange-400',
    'Critical': 'text-red-400'
  }
  return colorMap[severity] || 'text-gray-400'
}

const formatPatternType = (type) => {
  const typeMap = {
    'HotReload': 'Hot Reload',
    'AutoRestart': 'Auto Restart',
    'DevelopmentStack': 'Development Stack',
    'ResourceIntensive': 'Resource Intensive',
    'TimeBased': 'Time Based',
    'ProjectRelated': 'Project Related'
  }
  return typeMap[type] || type
}

const formatCategory = (category) => {
  const categoryMap = {
    'ProcessManagement': 'Process Management',
    'PortOptimization': 'Port Optimization',
    'ResourceOptimization': 'Resource Optimization',
    'WorkflowImprovement': 'Workflow Improvement',
    'IgnoreList': 'Ignore List'
  }
  return categoryMap[category] || category
}

const formatPriority = (priority) => {
  const priorityMap = {
    'Low': 'Low',
    'Medium': 'Medium',
    'High': 'High',
    'Critical': 'Critical'
  }
  return priorityMap[priority] || priority
}

const getPriorityColor = (priority) => {
  const colorMap = {
    'Low': 'text-green-400',
    'Medium': 'text-yellow-400',
    'High': 'text-orange-400',
    'Critical': 'text-red-400'
  }
  return colorMap[priority] || 'text-gray-400'
}

const clearHistory = async () => {
  if (confirm('Are you sure you want to clear all process history? This action cannot be undone.')) {
    try {
      isLoading.value = true
      await $fetch('/api/history/clear', { method: 'POST' })
      
      // Refresh the history after clearing
      if (processHistoryRef.value) {
        await processHistoryRef.value.fetchHistory()
      }
    } catch (error) {
      console.error('Failed to clear history:', error)
      alert('Failed to clear history. Please try again.')
    } finally {
      isLoading.value = false
    }
  }
}

const saveSettings = (newSettings) => {
  settings.value = { ...newSettings }
  // Restart monitoring with new settings
  refreshData()
  
  // Restart auto-refresh with new interval if it's enabled
  if (isAutoRefreshEnabled.value) {
    stopAutoRefresh()
    startAutoRefresh()
  }
}

// Watch for tab changes to load analytics data
watch(activeTab, (newTab) => {
  if (newTab !== 'history') {
    refreshAnalyticsData()
  }
})

// Lifecycle
onMounted(() => {
  if (isAutoRefreshEnabled.value) {
    startAutoRefresh()
  }
})

onUnmounted(() => {
  stopAutoRefresh()
})

// Meta
useHead({
  title: 'Process History',
  meta: [
    { name: 'description', content: 'Track and view process kill history' }
  ]
})
</script>
