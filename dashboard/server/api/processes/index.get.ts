import { spawn, exec, execSync } from 'child_process'
import { readFileSync, existsSync } from 'fs'
import { join } from 'path'
import { promisify } from 'util'

const execAsync = promisify(exec)

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  
  try {
    // Get query parameters
    const query = getQuery(event)
    const ports = query.ports || '2000-9000'
    const ignorePorts = query.ignorePorts || '5353'
    const ignoreProcesses = query.ignoreProcesses || ''
    const ignorePatterns = query.ignorePatterns || ''
    const ignoreGroups = query.ignoreGroups || ''
    const onlyGroups = query.onlyGroups || ''
    const smartFilter = query.smartFilter === 'true'
    const performance = query.performance === 'true'
    const showContext = query.showContext === 'true'
    const docker = query.docker === 'true'
    const verbose = query.verbose === 'true'
    const remoteMode = query.remoteMode === 'true' || config.remoteMode
    const remoteHost = query.remoteHost || config.remoteHost
    
    // Try to find the port-kill-console binary
    const binaryPath = findPortKillBinary(config.portKillBinaryPath)
    
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    // Use our Rust application for advanced process detection
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
      verbose,
      remoteMode,
      remoteHost
    )
    
    return {
      success: true,
      processes,
      count: processes.length,
      timestamp: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error fetching processes:', error)
    
    return {
      success: false,
      error: error.message,
      processes: [],
      count: 0,
      timestamp: new Date().toISOString()
    }
  }
})

function findPortKillBinary(defaultPath: string): string | null {
  // Check if the default path exists
  if (existsSync(defaultPath)) {
    return defaultPath
  }
  
  // Try common locations for port-kill-console
  const possiblePaths = [
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
  
  for (const path of possiblePaths) {
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
  verbose: boolean,
  remoteMode: boolean = false,
  remoteHost: string = ''
): Promise<any[]> {
  return new Promise((resolve, reject) => {
    // Build command arguments
    const args = [
      '--ports', ports,
      '--json' // We'll add JSON output to our Rust app
    ]
    
    // Add optional arguments
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
    
    // Add remote mode arguments
    if (remoteMode && remoteHost) {
      args.push('--remote', remoteHost)
    }
    
    const rustApp = spawn(binaryPath, args, {
      stdio: ['pipe', 'pipe', 'pipe']
    })
    
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
        // For now, fall back to the old method if Rust app fails
        console.warn(`Rust app failed with code ${code}: ${stderr}`)
        getProcessesWithLsof(ports, ignorePorts, ignoreProcesses, docker, verbose)
          .then(resolve)
          .catch(reject)
        return
      }
      
      try {
        // Parse JSON output from Rust app
        const lines = stdout.trim().split('\n')
        const processes = []
        
        for (const line of lines) {
          if (line.trim()) {
            try {
              const processData = JSON.parse(line)
              if (processData.pid && processData.port) {
                processes.push(processData)
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
      // Fall back to old method if spawn fails
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      getProcessesWithLsof(ports, ignorePorts, ignoreProcesses, docker, verbose)
        .then(resolve)
        .catch(reject)
    })
  })
}

async function getProcessesWithLsof(
  ports: string, 
  ignorePorts: string, 
  ignoreProcesses: string, 
  docker: boolean, 
  verbose: boolean
): Promise<any[]> {
  return new Promise((resolve, reject) => {
    // Parse port range
    let portArgs: string[]
    if (ports.includes(',')) {
      // Specific ports
      portArgs = ports.split(',').map(p => `:${p.trim()}`)
    } else if (ports.includes('-')) {
      // Port range
      const [start, end] = ports.split('-').map(Number)
      portArgs = []
      for (let port = start; port <= end; port++) {
        portArgs.push(`:${port}`)
      }
    } else {
      // Single port
      portArgs = [`:${ports}`]
    }
    
    // Build lsof command with multiple -i flags for each port
    const args = [
      '-sTCP:LISTEN',
      '-P', '-n'
    ]
    
    // Add -i flag for each port
    for (const port of portArgs) {
      args.push('-i', port)
    }
    
    const lsof = spawn('lsof', args, {
      stdio: ['pipe', 'pipe', 'pipe']
    })
    
    let stdout = ''
    let stderr = ''
    
    lsof.stdout.on('data', (data) => {
      stdout += data.toString()
    })
    
    lsof.stderr.on('data', (data) => {
      stderr += data.toString()
    })
    
    lsof.on('close', (code) => {
      if (code !== 0) {
        // Check if it's just "no processes found" (exit code 1 with empty stderr and empty stdout)
        if (code === 1 && !stderr.trim() && !stdout.trim()) {
          // No processes found - this is normal, return empty array
          resolve([])
          return
        }
        // If there's output, try to parse it even with exit code 1
        if (code === 1 && stdout.trim()) {
          try {
            const processes = parseLsofOutput(stdout, ignorePorts, ignoreProcesses, docker, verbose)
            resolve(processes)
            return
          } catch (error) {
            // If parsing fails, treat as error
          }
        }
        // Actual error occurred
        reject(new Error(`lsof failed with code ${code}: ${stderr}`))
        return
      }
      
      try {
        const processes = parseLsofOutput(stdout, ignorePorts, ignoreProcesses, docker, verbose)
        resolve(processes)
      } catch (error) {
        reject(error)
      }
    })
    
    lsof.on('error', (error) => {
      reject(error)
    })
  })
}

function parseLsofOutput(
  output: string, 
  ignorePorts: string, 
  ignoreProcesses: string, 
  docker: boolean, 
  verbose: boolean
): any[] {
  const processes: any[] = []
  const lines = output.split('\n')
  
  // Parse ignore lists
  const ignorePortsSet = new Set(ignorePorts.split(',').map(p => parseInt(p.trim())))
  const ignoreProcessesSet = new Set(ignoreProcesses.split(',').map(p => p.trim().toLowerCase()))
  
  for (let i = 1; i < lines.length; i++) { // Skip header
    const line = lines[i].trim()
    if (!line) continue
    
    const parts = line.split(/\s+/)
    if (parts.length < 9) continue
    
    const command = parts[0]
    const pid = parseInt(parts[1])
    const user = parts[2]
    const fd = parts[3]
    const type = parts[4]
    const device = parts[5]
    const size = parts[6]
    const node = parts[7]
    const name = parts[8]
    
    // Extract port from name (e.g., "*:3000" or "127.0.0.1:3000")
    const portMatch = name.match(/:(\d+)$/)
    if (!portMatch) continue
    
    const port = parseInt(portMatch[1])
    
    // Check if should be ignored
    if (ignorePortsSet.has(port) || ignoreProcessesSet.has(command.toLowerCase())) {
      continue
    }
    
    // Extract process name
    const processName = command.split('/').pop() || command
    
    // Get additional process info if verbose
    let commandLine = null
    let workingDirectory = null
    let containerId = null
    let containerName = null

    if (verbose) {
      try {
        // Get full command line using ps
        try {
          const psOutput = execSync(`ps -p ${pid} -o command=`, { encoding: 'utf8', timeout: 1000 })
          commandLine = psOutput.trim()
        } catch (e) {
          commandLine = command
        }
        
        // Get working directory using lsof (cross-platform approach)
        try {
          const lsofOutput = execSync(`lsof -p ${pid} -d cwd -F p -F n`, { encoding: 'utf8', timeout: 1000 })
          const lines = lsofOutput.split('\n')
          let foundPid = false
          let foundCwd = false
          
          for (const line of lines) {
            if (line.startsWith('p') && line.substring(1) === pid.toString()) {
              foundPid = true
            } else if (foundPid && line === 'fcwd') {
              foundCwd = true
            } else if (foundPid && foundCwd && line.startsWith('n')) {
              const dir = line.substring(1) // Remove the 'n' prefix
              if (dir && dir !== '/' && dir !== '') {
                // Truncate the directory path to show only the last part
                const pathParts = dir.split('/')
                workingDirectory = pathParts.length > 3 ? 
                  `.../${pathParts.slice(-2).join('/')}` : dir
                break
              }
            } else if (line.startsWith('p') && line.substring(1) !== pid.toString()) {
              // We've moved to a different PID, reset
              foundPid = false
              foundCwd = false
            }
          }
        } catch (e) {
          // lsof failed, working directory will remain null
        }
      } catch (e) {
        // Fallback to basic command
        commandLine = command
        workingDirectory = null
      }
    }
    
    // Check if process is running inside a Docker container
    if (docker) {
      try {
        // First, check if this is a Docker daemon process
        if (command.includes('docker') || command.includes('com.docke')) {
          // This is a Docker daemon process, mark as Docker-related
          containerId = 'docker-daemon'
          containerName = 'Docker Daemon'
        } else {
          // For non-Docker processes, check if they're actually running inside a container
          // by checking if their working directory is inside a container path
          if (workingDirectory && workingDirectory.includes('com.docker.docker')) {
            // This process is running inside a Docker container
            // Find which container by checking port mappings
            try {
              const dockerPsOutput = execSync(`docker ps --format "{{.ID}} {{.Names}} {{.Ports}}"`, { encoding: 'utf8', timeout: 2000 })
              const lines = dockerPsOutput.trim().split('\n')
              
              for (const line of lines) {
                // Look for port mapping like "0.0.0.0:3000->3000/tcp"
                if (line.includes(`:${port}->`) || line.includes(`:${port}/`)) {
                  // Split by spaces and take first two parts (ID and Name)
                  const parts = line.trim().split(/\s+/)
                  if (parts.length >= 2) {
                    containerId = parts[0]
                    containerName = parts[1]
                    break
                  }
                }
              }
            } catch (e) {
              // Docker ps command failed
            }
          } else {
            // This is a host process (not in a container), give it a descriptive label
            containerId = 'host-process'
            containerName = 'Host Process'
          }
        }
      } catch (e) {
        // Docker detection failed
      }
    }
    
    processes.push({
      pid,
      port,
      command,
      name: processName,
      container_id: containerId,
      container_name: containerName,
      command_line: commandLine,
      working_directory: workingDirectory
    })
  }
  
  return processes
}

async function getProcessesWithNetstat(
  ports: string,
  ignorePorts: string,
  ignoreProcesses: string,
  docker: boolean,
  verbose: boolean
): Promise<any[]> {
  return new Promise((resolve, reject) => {
    // Parse port list
    const portList = ports.split(',').map(p => parseInt(p.trim()))
    
    // Build netstat command
    const netstat = spawn('netstat', ['-ano'], {
      stdio: ['pipe', 'pipe', 'pipe']
    })

    let stdout = ''
    let stderr = ''

    netstat.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    netstat.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    netstat.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`netstat failed with code ${code}: ${stderr}`))
        return
      }

      try {
        const processes = parseNetstatOutput(stdout, portList, ignorePorts, ignoreProcesses, docker, verbose)
        resolve(processes)
      } catch (error) {
        reject(error)
      }
    })

    netstat.on('error', (error) => {
      reject(error)
    })
  })
}

function parseNetstatOutput(
  output: string,
  portList: number[],
  ignorePorts: string,
  ignoreProcesses: string,
  docker: boolean,
  verbose: boolean
): any[] {
  const processes: any[] = []
  const lines = output.split('\n')

  // Parse ignore lists
  const ignorePortsSet = new Set(ignorePorts.split(',').map(p => parseInt(p.trim())))
  const ignoreProcessesSet = new Set(ignoreProcesses.split(',').map(p => p.trim().toLowerCase()))

  for (const line of lines) {
    const trimmedLine = line.trim()
    if (!trimmedLine) continue

    const parts = trimmedLine.split(/\s+/)
    if (parts.length < 5) continue

    // Check if this is a listening connection
    if (parts[0] !== 'TCP' && parts[0] !== 'UDP') continue
    if (parts[3] !== 'LISTENING') continue

    // Extract port from local address (e.g., "0.0.0.0:3000")
    const localAddress = parts[1]
    const portMatch = localAddress.match(/:(\d+)$/)
    if (!portMatch) continue

    const port = parseInt(portMatch[1])
    
    // Check if this port is in our monitoring list
    if (!portList.includes(port)) continue

    // Check if should be ignored
    if (ignorePortsSet.has(port)) continue

    const pid = parseInt(parts[4])
    if (isNaN(pid)) continue

    // Get process name using tasklist
    const processName = getProcessNameFromPid(pid)
    
    // Check if process should be ignored
    if (ignoreProcessesSet.has(processName.toLowerCase())) continue

    processes.push({
      pid,
      port,
      command: processName,
      name: processName,
      container_id: null, // Docker detection would need additional work on Windows
      container_name: null,
      command_line: verbose ? processName : null,
      working_directory: null
    })
  }

  return processes
}

function getProcessNameFromPid(pid: number): string {
  try {
    const { execSync } = require('child_process')
    const output = execSync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, { encoding: 'utf8', timeout: 1000 })
    const lines = output.trim().split('\n')
    if (lines.length > 0) {
      const parts = lines[0].split(',')
      if (parts.length > 0) {
        return parts[0].replace(/"/g, '')
      }
    }
  } catch (e) {
    // Fallback if tasklist fails
  }
  return `PID-${pid}`
}