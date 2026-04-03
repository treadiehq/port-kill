# Port Kill Dashboard

A modern web dashboard for monitoring and managing development processes and ports, built with Nuxt.js and Tailwind CSS. This dashboard provides a comprehensive interface for the Port Kill Rust application, offering real-time process monitoring, advanced filtering, and process management capabilities.

## Features

### 🚀 Core Features

- **Real-time Process Monitoring**: Live updates of all running processes on monitored ports
- **Advanced Filtering**: Search by process name, port, PID, or container name
- **Process Management**: Kill individual processes or all processes at once
- **Port Range Configuration**: Monitor specific ports or port ranges
- **Docker Integration**: Monitor and manage Docker containers
- **System Resource Monitoring**: Real-time CPU, memory, and disk usage tracking

## Prerequisites

- Node.js 20.19.0 or later
- npm or yarn package manager
- Port Kill Rust application (built and available)
  - **Windows**: The binary should be at `target\release\port-kill-console.exe`
  - **macOS/Linux**: The binary should be at `target/release/port-kill-console`

## Installation

1. **From the project root, build the Port Kill binary:**
   ```bash
   cargo build --release
   ```

2. **Navigate to the dashboard directory and install dependencies:**
   ```bash
   cd dashboard
   npm install
   ```

3. **Start the dashboard development server:**
   ```bash
   npm run dev
   ```

4. **Open your browser:**
   Navigate to `http://localhost:3002`

> The dashboard directly executes `port-kill-console`; you do not need to run `cargo run --release` in a separate terminal.

## Configuration

The dashboard can be configured through the settings panel or environment variables:

### Environment Variables

Create a `.env` file in the dashboard root:

```env
# Port Kill binary path (optional, will auto-detect)
PORT_KILL_BINARY_PATH=../target/release/port-kill-console

# API base URL (optional)
API_BASE=http://localhost:3001/api
```



## Dashboard Walkthrough

### 🎯 Header Section

#### **Connection Status (Green/Red Dot + "Connected/Disconnected")**
- **Green dot + "Connected"**: Dashboard is successfully connected to the Rust backend
- **Red dot + "Disconnected"**: Backend isn't running or connection failed
- Indicates real-time data flow status

#### **Refresh Button** 
- Manual refresh button to immediately update all data
- Useful when you want to see the latest process information without waiting for auto-refresh


### 📊 Stats Overview Cards 

#### System Load
- Displays current system load status
- Shows "Normal" when system is running smoothly
- Would show "High" or "Critical" if system is under heavy load


### 💻 System Resources Section

#### Header with "Live" Status**
- **"Live" indicator**: Shows real-time data is being updated
- **Refresh button**: Manual refresh for system resources
- Updates every 5 seconds automatically

#### Resource Cards

##### CPU Usage
- **Current**: Shows CPU usage percentage
- **Cores**: Number of CPU cores available
- **Load**: System load average
- **Progress bar**: Visual representation of CPU usage

##### Memory Usage
- **Current**: Shows memory usage percentage
- **Used/Total**: Memory usage in bytes (formatted as KB/MB/GB)
- **Progress bar**: Visual memory usage indicator

##### Disk Usage
- **Current**: Shows disk usage percentage
- **Used/Total**: Disk space usage
- **Progress bar**: Visual disk usage indicator

##### System Uptime (Yellow Card)
- **Current**: Shows how long the system has been running
- **Last updated**: Timestamp of last data refresh
- **Format**: Shows in minutes, hours, or days

#### Load Average Chart
- **1 min, 5 min, 15 min**: System load averages over different time periods
- **Color-coded**: Blue, Green, Purple for easy reading
- **Purpose**: Shows system performance trends

**Load Average Explanation:**
- **Normal range**: 0.00-1.00 per CPU core (you have 14 cores, so normal would be 0-14)
- **Your current load**: 4.09 means your system is working at about 29% capacity
- **High load**: Values above 1.0 per core indicate the system is under stress
- **Trend analysis**: Compare 1min vs 5min vs 15min to see if load is increasing or decreasing

