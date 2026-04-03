import { spawn, exec, execSync } from 'child_process'
import { existsSync } from 'fs'
import { promisify } from 'util'

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  try {
    // Get query parameters to determine which processes to kill
    const query = getQuery(event)
    const ports = String(query.ports || '2000-9000')
    const ignorePorts = String(query.ignorePorts || '5353')
    const ignoreProcesses = String(query.ignoreProcesses || '')
    const ignorePatterns = String(query.ignorePatterns || '')
    const ignoreGroups = String(query.ignoreGroups || '')
    const onlyGroups = String(query.onlyGroups || '')
    const smartFilter = query.smartFilter === 'true' || query.smartFilter === true
    const performance = query.performance === 'true' || query.performance === true
    const showContext = query.showContext === 'true' || query.showContext === true
    const docker = query.docker === 'true' || query.docker === true
    const verbose = query.verbose === 'true' || query.verbose === true
    
    console.log('Kill-all API called with ports:', ports)
    console.log('Binary path:', config.portKillBinaryPath)
    
    // Find the correct binary path
    const binaryPath = findPortKillBinary(config.portKillBinaryPath)
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    console.log('Using binary path:', binaryPath)
    
    // First, get all processes using the Rust application
    const processes = await getProcessesWithRustApp(
      binaryPath,
      ports,
      ignorePorts,
      ignoreProcesses,
      ignorePatterns,
      ignoreGroups,
      onlyGroups,
      smartFilter,
      performance,
      showContext,
      docker,
      verbose
    )
    
    console.log('Found processes:', processes.length)
    
    if (processes.length === 0) {
      return {
        success: true,
        message: 'No processes found to kill',
        killedCount: 0,
        timestamp: new Date().toISOString()
      }
    }
    
    // Kill all processes using the Rust application
    const results = await killAllProcessesWithRustApp(
      binaryPath,
      ports,
      ignorePorts,
      ignoreProcesses,
      ignorePatterns,
      ignoreGroups,
      onlyGroups,
      smartFilter,
      performance,
      showContext,
      docker,
      verbose
    )
    
    return {
      success: true,
      message: `Killed ${results.killedCount} processes${results.failedCount > 0 ? `, ${results.failedCount} failed` : ''}`,
      killedCount: results.killedCount,
      failedCount: results.failedCount,
      timestamp: new Date().toISOString()
    }
    
  } catch (error: any) {
    console.error('Error killing all processes:', error)
    
    throw createError({
      statusCode: 500,
      statusMessage: `Failed to kill all processes: ${error.message}`
    })
  }
})

function findPortKillBinary(defaultPath: string): string | null {
  // Check if the default path exists
  if (existsSync(defaultPath)) {
    return defaultPath
  }
  
  // Try common locations
  const commonPaths = [
    './target/release/port-kill-console',
    './target/release/port-kill-console.exe',
    './target/debug/port-kill-console',
    './target/debug/port-kill-console.exe',
    '../target/release/port-kill-console',
    '../target/release/port-kill-console.exe',
    '../target/debug/port-kill-console',
    '../target/debug/port-kill-console.exe',
    '/usr/local/bin/port-kill-console',
    '/opt/homebrew/bin/port-kill-console',
    join(process.env.HOME || '', '.local', 'bin', 'port-kill-console'),
    'C:\\Program Files\\port-kill\\port-kill-console.exe',
    join(process.env.USERPROFILE || '', 'AppData', 'Local', 'port-kill', 'port-kill-console.exe')
  ]
  
  for (const path of commonPaths) {
    if (existsSync(path)) {
      return path
    }
  }
  
  return null
}

async function getProcessesWithRustApp(
  binaryPath: string,
  ports: string,
  ignorePorts: string,
  ignoreProcesses: string,
  ignorePatterns: string,
  ignoreGroups: string,
  onlyGroups: string,
  smartFilter: boolean,
  performance: boolean,
  showContext: boolean,
  docker: boolean,
  verbose: boolean
): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const args = [
      '--ports', ports,
      '--json'
    ]
    if (ignorePorts) args.push('--ignore-ports', ignorePorts)
    if (ignoreProcesses) args.push('--ignore-processes', ignoreProcesses)
    if (ignorePatterns) args.push('--ignore-patterns', ignorePatterns)
    if (ignoreGroups) args.push('--ignore-groups', ignoreGroups)
    if (onlyGroups) args.push('--only-groups', onlyGroups)
    if (smartFilter) args.push('--smart-filter')
    if (performance) args.push('--performance')
    if (showContext) args.push('--show-context')
    if (docker) args.push('--docker')
    if (verbose) args.push('--verbose')

    const rustApp = spawn(binaryPath, args, { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    
    rustApp.stdout.on('data', (data) => {
      stdout += data.toString()
    })
    
    rustApp.stderr.on('data', (data) => {
      stderr += data.toString()
    })
    
    rustApp.on('close', (code) => {
      if (code !== 0) {
        console.warn(`Rust app failed with code ${code}: ${stderr}`)
        // Fallback to empty array if Rust app fails
        resolve([])
        return
      }
      
      try {
        const lines = stdout.trim().split('\n')
        const processes = []
        for (const line of lines) {
          if (line.trim()) {
            try {
              const process = JSON.parse(line)
              if (process.pid && process.port) {
                processes.push(process)
              }
            } catch (e) {
              // Skip invalid JSON lines
            }
          }
        }
        resolve(processes)
      } catch (error) {
        reject(error)
      }
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      // Fallback to empty array if spawn fails
      resolve([])
    })
  })
}

async function killAllProcessesWithRustApp(
  binaryPath: string,
  ports: string,
  ignorePorts: string,
  ignoreProcesses: string,
  ignorePatterns: string,
  ignoreGroups: string,
  onlyGroups: string,
  smartFilter: boolean,
  performance: boolean,
  showContext: boolean,
  docker: boolean,
  verbose: boolean
): Promise<{ killedCount: number; failedCount: number }> {
  return new Promise((resolve, reject) => {
    // Use the new --kill-all command
    const args = [
      '--ports', ports,
      '--kill-all'
    ]
    if (ignorePorts) args.push('--ignore-ports', ignorePorts)
    if (ignoreProcesses) args.push('--ignore-processes', ignoreProcesses)
    if (ignorePatterns) args.push('--ignore-patterns', ignorePatterns)
    if (ignoreGroups) args.push('--ignore-groups', ignoreGroups)
    if (onlyGroups) args.push('--only-groups', onlyGroups)
    if (smartFilter) args.push('--smart-filter')
    if (performance) args.push('--performance')
    if (showContext) args.push('--show-context')
    if (docker) args.push('--docker')
    if (verbose) args.push('--verbose')

    const rustApp = spawn(binaryPath, args, { 
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 10000 // 10 second timeout
    })
    
    let stdout = ''
    let stderr = ''
    let killedCount = 0
    let failedCount = 0
    
    rustApp.stdout.on('data', (data) => {
      const output = data.toString()
      stdout += output
      
      // Count killed processes from output
      const killMatches = output.match(/✅ Killed \d+\/\d+ processes/g)
      if (killMatches) {
        const match = killMatches[0]
        const countMatch = match.match(/✅ Killed (\d+)\/\d+ processes/)
        if (countMatch) {
          killedCount = parseInt(countMatch[1])
        }
      }
      
      const failMatches = output.match(/❌ Failed to kill/g)
      if (failMatches) {
        failedCount += failMatches.length
      }
    })
    
    rustApp.stderr.on('data', (data) => {
      stderr += data.toString()
    })
    
    rustApp.on('close', (code) => {
      if (code !== 0) {
        console.warn(`Rust app failed with code ${code}: ${stderr}`)
        // Still return the counts we managed to get
      }
      
      resolve({ killedCount, failedCount })
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      resolve({ killedCount: 0, failedCount: 0 })
    })
  })
}