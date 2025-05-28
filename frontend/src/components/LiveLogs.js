import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  CircularProgress,
  Alert,
} from '@mui/material';

const LiveLogs = () => {
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState('disconnected');
  const [error, setError] = useState(null);
  const [connectedComputer, setConnectedComputer] = useState(null);

  useEffect(() => {
    let eventSource = null;

    const connectSSE = () => {
    try {
      setStatus('connecting');
        console.log('Connecting to SSE endpoint...');
        eventSource = new EventSource('http://localhost:8000/live-logs');

        eventSource.onopen = () => {
          console.log('Connected to logs SSE');
          setStatus('connected');
          setError(null);
        };

        eventSource.onerror = (event) => {
          console.error('SSE error:', event);
          setError('Failed to connect to logs server');
          setStatus('error');
          setConnectedComputer(null);
          eventSource.close();
        
        // Attempt to reconnect after 5 seconds
          setTimeout(connectSSE, 5000);
      };

        eventSource.onmessage = (event) => {
        try {
            console.log('Received SSE message:', event.data);
          const data = JSON.parse(event.data);
          
            // Format the log data
            const formattedLog = {
              _id: data._id || Date.now().toString(),
              TimeGenerated: data.TimeGenerated || 'N/A',
              EventID: data.EventID || 'N/A',
              EventType: data.EventType || 'N/A',
              SourceName: data.SourceName || 'N/A',
              ComputerName: data.ComputerName || 'N/A',
              Channel: data.Channel || 'N/A',
              Message: data.Message || 'N/A',
              EventCategory: data.EventCategory || 'N/A',
              RecordNumber: data.RecordNumber || 'N/A'
            };

            // Update connected computer name if available
            if (formattedLog.ComputerName && formattedLog.ComputerName !== 'N/A') {
              setConnectedComputer(formattedLog.ComputerName);
            }

            setLogs(prevLogs => {
              const newLogs = [formattedLog, ...prevLogs].slice(0, 100);
              console.log('Updated logs:', newLogs);
              return newLogs;
            });
        } catch (err) {
            console.error('Error parsing SSE message:', err, event.data);
        }
      };
    } catch (err) {
        console.error('Error creating SSE connection:', err);
        setError('Failed to create SSE connection');
      setStatus('error');
      setConnectedComputer(null);
    }
  };

    connectSSE();

    return () => {
      if (eventSource) {
        console.log('Closing SSE connection');
        eventSource.close();
      }
    };
  }, []);

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h5" component="h1">
          Live Security Logs
        </Typography>
        <Box 
          sx={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: 2,
            bgcolor: 'white',
            borderRadius: '12px',
            px: 2,
            py: 1,
            boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
            transition: 'all 0.3s ease',
            border: '2px solid',
            borderColor: status === 'connected' ? 'success.main' : 'error.main',
            '&:hover': {
              boxShadow: '0 4px 8px rgba(0,0,0,0.15)',
              transform: 'translateY(-1px)'
            }
          }}
        >
          {status === 'connected' && (
            <Box
              sx={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                bgcolor: 'success.main',
                mr: 1,
                boxShadow: '0 0 8px rgba(76, 175, 80, 0.5)'
              }}
            />
          )}
          <Typography
            sx={{
              color: 'text.primary',
              fontWeight: 'bold',
              fontSize: '0.95rem',
              letterSpacing: '0.5px',
              '& .status-text': {
                color: status === 'connected' ? 'success.main' : 'error.main',
                ml: 0.5
              }
            }}
          >
            {status === 'connected' && connectedComputer ? 
              <>{connectedComputer}<span className="status-text">Connected</span></> : 
              status}
          </Typography>
          {status === 'connecting' && (
            <CircularProgress 
              size={20} 
              sx={{ 
                color: 'error.main',
                ml: 1
              }} 
            />
          )}
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Timestamp</TableCell>
              <TableCell>Event ID</TableCell>
              <TableCell>Event Type</TableCell>
              <TableCell>Source</TableCell>
              <TableCell>Computer</TableCell>
              <TableCell>Channel</TableCell>
              <TableCell>Message</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {logs.map((log) => (
              <TableRow key={log._id}>
                <TableCell>{log.TimeGenerated}</TableCell>
                <TableCell>{log.EventID}</TableCell>
                <TableCell>{log.EventType}</TableCell>
                <TableCell>{log.SourceName}</TableCell>
                <TableCell>{log.ComputerName}</TableCell>
                <TableCell>{log.Channel}</TableCell>
                <TableCell style={{ whiteSpace: 'pre-wrap', maxWidth: '400px' }}>{log.Message}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default LiveLogs; 