// external_program.go

package main

import (
    "fmt"
    "net"
    "os"
    "os/exec"
)

var (
    socketPath = "/var/run/redis/lom_unix_socket" // Temporary. change it to proper path
)

func main() {
    // Create a Unix domain socket
    os.Remove(socketPath)
    listener, err := net.Listen("unix", socketPath)
    if err != nil {
        fmt.Printf("Failed to create socket: %s\n", err)
        return
    }
    defer listener.Close()

    fmt.Println("Listening for commands...")

    for {
        // Accept incoming connections
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("Failed to accept connection: %s\n", err)
            continue
        }

        // Read the command from the connection
        buf := make([]byte, 1024)
        n, err := conn.Read(buf)
        if err != nil {
            fmt.Printf("Failed to read command: %s\n", err)
            continue
        }

        // Execute the command on the host OS
        command := string(buf[:n])
        cmd := exec.Command("sh", "-c", command)
        output, err := cmd.CombinedOutput()
        if err != nil {
            fmt.Printf("Failed to execute command: %s, error :  %s\n", command, err)
        } else {
            fmt.Printf("Command executed successfully: %s, output : %s\n", command, string(output))
        }

        // Send the output back to the container
        conn.Write(output)

        conn.Close()
    }
}
