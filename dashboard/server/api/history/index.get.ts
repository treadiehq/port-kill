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
    const limit = parseInt(query.limit as string) || 50
    const group = query.group as string || ''
    const project = query.project as string || ''
    
    // Try to find the port-kill-console binary
    const binaryPath = findPortKillBinary(config.portKillBinaryPath)
    
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    // Get process history from our Rust application
    const history = await getProcessHistory(binaryPath, limit, group, project)
    
    return {
      success: true,
      history,
      count: history.length,
      timestamp: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error fetching process history:', error)
    
    return {
      success: false,
      error: error.message,
      history: [],
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

async function getProcessHistory(
  binaryPath: string,
  limit: number,
  group: string,
  project: string
): Promise<any[]> {
  return new Promise((resolve, reject) => {
    // Build command arguments for history
    const args = [
      '--show-history',
      '--json'
    ]
    
    // Add optional filters
    if (group) args.push('--only-groups', group)
    if (project) args.push('--project', project)
    
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
        // For now, return empty history if Rust app fails
        console.warn(`Rust app failed with code ${code}: ${stderr}`)
        resolve([])
        return
      }
      
      try {
        // Parse JSON output from Rust app
        const lines = stdout.trim().split('\n')
        const history = []
        
        for (const line of lines) {
          if (line.trim()) {
            try {
              const historyEntry = JSON.parse(line)
              if (historyEntry.pid && historyEntry.port) {
                history.push(historyEntry)
              }
            } catch (e) {
              // Skip invalid JSON lines
            }
          }
        }
        
        // Limit results
        const limitedHistory = history.slice(0, limit)
        resolve(limitedHistory)
      } catch (error) {
        reject(error)
      }
    })
    
    rustApp.on('error', (error) => {
      // Return empty history if spawn fails
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      resolve([])
    })
  })
}
