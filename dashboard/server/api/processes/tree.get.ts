import { spawn, exec, execSync } from 'child_process'
import { existsSync } from 'fs'
import { promisify } from 'util'

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  try {
    // Get query parameters
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
    
    // Find the correct binary path
    const binaryPath = findPortKillBinary(config.portKillBinaryPath)
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    // Get process tree using the Rust application
    const treeOutput = await getProcessTreeWithRustApp(
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
      tree: treeOutput,
      timestamp: new Date().toISOString()
    }
    
  } catch (error: any) {
    console.error('Error getting process tree:', error)
    
    throw createError({
      statusCode: 500,
      statusMessage: `Failed to get process tree: ${error.message}`
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

async function getProcessTreeWithRustApp(
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
): Promise<string> {
  return new Promise((resolve, reject) => {
    const args = [
      '--ports', ports,
      '--show-tree'
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
      timeout: 10000
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
        console.warn(`Rust app failed with code ${code}: ${stderr}`)
        resolve('Failed to get process tree')
        return
      }
      
      resolve(stdout)
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      resolve('Failed to get process tree')
    })
  })
}
