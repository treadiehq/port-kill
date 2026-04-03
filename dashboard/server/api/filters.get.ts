import { spawn } from 'child_process'
import { existsSync } from 'fs'

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  
  try {
    // Find the correct binary path
    const binaryPath = findPortKillBinary(config.portKillBinaryPath)
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    // Get filter information using the Rust application
    const filtersOutput = await getFiltersWithRustApp(binaryPath)
    
    return {
      success: true,
      filters: filtersOutput,
      timestamp: new Date().toISOString()
    }
    
  } catch (error: any) {
    console.error('Error getting filter information:', error)
    
    throw createError({
      statusCode: 500,
      statusMessage: `Failed to get filter information: ${error.message}`
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

async function getFiltersWithRustApp(binaryPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const args = ['--show-filters']

    const rustApp = spawn(binaryPath, args, { 
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 5000
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
        resolve('Failed to get filter information')
        return
      }
      
      resolve(stdout)
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      resolve('Failed to get filter information')
    })
  })
}
