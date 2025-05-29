import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/auth/ProtectedRoute';
import Login from './components/auth/Login';
import Dashboard from './components/dashboard/Dashboard';
import LogList from './components/logs/LogList';
import LogDetail from './components/logs/LogDetail';
import Layout from './components/common/Layout';
import LiveLogs from './components/LiveLogs';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import './App.css';
import Profile from './components/profile/Profile';
import QueueList from './components/analyst/QueueList';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#2563eb', // blue-600
    },
    secondary: {
      main: '#4b5563', // gray-600
    },
    background: {
      default: '#f9fafb', // gray-50
      paper: '#ffffff',
    },
  },
  typography: {
    fontFamily: '"Inter", "Helvetica", "Arial", sans-serif',
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
        },
      },
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
    <AuthProvider>
        <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <Layout>
                    <Dashboard />
                  </Layout>
                </ProtectedRoute>
              }
            />
            <Route
              path="/logs"
              element={
                <ProtectedRoute>
                  <Layout>
                    <LogList />
                  </Layout>
                </ProtectedRoute>
              }
            />
            <Route
              path="/logs/:id"
              element={
                <ProtectedRoute>
                  <Layout>
                    <LogDetail />
                  </Layout>
                </ProtectedRoute>
              }
            />
            <Route
              path="/live-logs"
              element={
                <ProtectedRoute>
                  <Layout>
                    <LiveLogs />
                  </Layout>
                </ProtectedRoute>
              }
            />
            <Route
              path="/analyst-queue"
              element={
                <ProtectedRoute>
                  <Layout>
                    <QueueList />
                  </Layout>
                </ProtectedRoute>
              }
            />
            <Route path="/profile" element={<ProtectedRoute><Profile /></ProtectedRoute>} />
          </Routes>
      </Router>
    </AuthProvider>
    </ThemeProvider>
  );
}

export default App;