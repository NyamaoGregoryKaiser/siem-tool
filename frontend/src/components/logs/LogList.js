import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  ServerIcon,
  EyeIcon,
} from '@heroicons/react/24/outline';
import api from '../../services/api';

const LogList = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [computerNames, setComputerNames] = useState([]);
  const [deviceStats, setDeviceStats] = useState({});
  const [severityLogs, setSeverityLogs] = useState({});
  const [filters, setFilters] = useState({
    search: '',
    severity: '',
    device_name: '',
    source_ip: '',
    start_date: '',
    end_date: '',
    sort_order: 'desc'
  });
  const [pagination, setPagination] = useState({
    page: 1,
    totalPages: 1,
    totalCount: 0,
  });

  // Fetch computer names
  const fetchComputerNames = async () => {
    try {
      const response = await api.get('/logs/computer-names/');
      setComputerNames(response.data);
    } catch (error) {
      console.error('Error fetching computer names:', error);
    }
  };

  const fetchDeviceStats = async () => {
    try {
      const response = await api.get('/logs/analytics/alerts-by-agent');
      const stats = {};
      response.data.forEach(item => {
        stats[item.agent] = item.count;
      });
      setDeviceStats(stats);
    } catch (error) {
      console.error('Error fetching device stats:', error);
    }
  };

  const fetchSeverityLogs = async () => {
    try {
      const response = await api.get('/logs/analytics/critical-logs-by-device');
      setSeverityLogs(response.data);
    } catch (error) {
      console.error('Error fetching severity logs:', error);
    }
  };

  useEffect(() => {
    fetchComputerNames();
    fetchDeviceStats();
    fetchSeverityLogs();

    // Set up periodic refresh of severity logs
    const intervalId = setInterval(fetchSeverityLogs, 60000); // Refresh every minute

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
  }, []);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      setError(null);
      const params = new URLSearchParams();
      
      // Map frontend filter keys to backend query parameters
      const filterMapping = {
        search: 'search',
        severity: 'severity',
        device_name: 'ComputerName',
        source_ip: 'source_ip',
        start_date: 'start_date',
        end_date: 'end_date',
        sort_order: 'sort_order'
      };
      
      // Map severity values based on EventType
      const severityMapping = {
        'critical': { event_type: 'FailureAudit' },
        'high': { event_type: 'Warning' },
        'moderate': { event_type: 'Error' },
        'low': { event_type: ['SuccessAudit', 'Information', 'Success'] }
      };
      
      Object.keys(filters).forEach(key => {
        if (filters[key]) {
          if (key === 'severity') {
            const severity = severityMapping[filters[key]];
            if (Array.isArray(severity.event_type)) {
              severity.event_type.forEach(type => {
                params.append('EventType', type);
              });
            } else {
              params.append('EventType', severity.event_type);
            }
          } else if (key === 'start_date' || key === 'end_date') {
            // Convert datetime-local input to match TimeGenerated format
            const date = new Date(filters[key]);
            const formattedDate = date.toLocaleString('en-US', {
              year: 'numeric',
              month: '2-digit',
              day: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
              hour12: false,
              timeZone: 'Africa/Nairobi'
            }).replace(',', '');
            params.append(filterMapping[key], formattedDate);
          } else if (key === 'sort_order') {
            params.append('sort_order', filters[key]);
          } else {
            params.append(filterMapping[key], filters[key]);
          }
        }
      });
      
      params.append('page', pagination.page);
      params.append('page_size', 20);

      const response = await api.get(`/logs/?${params.toString()}`);
      setLogs(response.data.logs || []);
      setPagination(prev => ({
        ...prev,
        totalPages: Math.ceil((response.data.total || 0) / 20),
        totalCount: response.data.total || 0,
      }));
    } catch (error) {
      console.error('Error fetching logs:', error);
      setError(error.response?.data?.message || 'Failed to fetch logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [pagination.page]);

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const handleSearch = (e) => {
    e.preventDefault();
    setPagination(prev => ({ ...prev, page: 1 }));
    fetchLogs();
  };

  const clearFilters = () => {
    setFilters({
      search: '',
      severity: '',
      device_name: '',
      source_ip: '',
      start_date: '',
      end_date: '',
      sort_order: 'desc'
    });
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const getSeverityColor = (level, eventType, status) => {
    if (eventType === 'FailureAudit') {
      return 'bg-red-100 text-red-800 border-red-200';
    }
    if (eventType === 'Warning') {
      return 'bg-orange-100 text-orange-800 border-orange-200';
    }
    if (eventType === 'Error') {
      return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    }
    if (['SuccessAudit', 'Information', 'Success'].includes(eventType)) {
      return 'bg-green-100 text-green-800 border-green-200';
    }
    return 'bg-gray-100 text-gray-800 border-gray-200';
  };

  const getSeverityLabel = (level, eventType, status) => {
    if (eventType === 'FailureAudit') {
      return 'Critical';
    }
    if (eventType === 'Warning') {
      return 'High';
    }
    if (eventType === 'Error') {
      return 'Moderate';
    }
    if (['SuccessAudit', 'Information', 'Success'].includes(eventType)) {
      return 'Low';
    }
    return 'Unknown';
  };

  const getTechnique = (level, eventType, status) => {
    if (level === 1 || eventType === 'Error' || status === 'Critical' ||
        level === 2 || eventType === 'Warning' || eventType === 'FailureAudit' || status === 'High') {
      const techniques = ['T1078', 'T1110', 'T1110.001', 'T1021.004', 'T1218', 'T1098'];
      return techniques[Math.floor(Math.random() * techniques.length)];
    }
    return null;
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="md:flex md:items-center md:justify-between">
        <div className="flex-1 min-w-0">
          <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl">
            Security Logs
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            Monitor and analyze security events in real-time
          </p>
        </div>
        <div className="mt-4 flex md:mt-0 md:ml-4">
          <span className="text-sm text-gray-500">
            {pagination.totalCount.toLocaleString()} total logs
          </span>
        </div>
      </div>

      {/* Device Stats Cards */}
      <div className="grid grid-cols-5 gap-2">
        {computerNames.map((device) => (
          <div key={device} className="bg-white rounded-lg shadow-sm border border-gray-200 p-2 hover:shadow-md transition-shadow duration-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-1.5">
                <div className="bg-blue-100 p-1 rounded-lg">
                  <ServerIcon className="h-3.5 w-3.5 text-blue-600" />
                </div>
                <div>
                  <h3 className="text-[11px] font-medium text-gray-900 truncate max-w-[90px]">
                    {device}
                  </h3>
                  <p className="text-[9px] text-gray-500">Device</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-base font-bold text-gray-900">
                  {deviceStats[device]?.toLocaleString() || 0}
                </p>
                <p className="text-[9px] text-gray-500">Total Logs</p>
              </div>
            </div>
            <div className="mt-1.5 pt-1.5 border-t border-gray-100">
              <div className="flex flex-col gap-1">
                <div className="flex justify-between text-[9px] text-gray-500">
                  <span>Critical (24h)</span>
                  <span className="text-red-600 font-medium">
                    {severityLogs[device]?.critical || 0}
                  </span>
                </div>
                <div className="flex justify-between text-[9px] text-gray-500">
                  <span>High (24h)</span>
                  <span className="text-orange-600 font-medium">
                    {severityLogs[device]?.high || 0}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-400" />
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <div className="mt-2 text-sm text-red-700">
                <p>{error}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium text-gray-900">Filters</h3>
          <button
            onClick={clearFilters}
            className="text-sm text-blue-600 hover:text-blue-800"
          >
            Clear All
          </button>
        </div>
        
        <form onSubmit={handleSearch}>
          <div className="grid grid-cols-8 gap-2 items-end">
            {/* Search */}
            <div className="col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Search
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  placeholder="Search logs..."
                  className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <MagnifyingGlassIcon className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
              </div>
            </div>

            {/* Sort Order */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Sort Order
              </label>
              <select
                value={filters.sort_order}
                onChange={(e) => handleFilterChange('sort_order', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="desc">Latest First</option>
                <option value="asc">Earliest First</option>
              </select>
            </div>

            {/* Severity */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Severity
              </label>
              <select
                value={filters.severity}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="moderate">Moderate</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Device Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Device Name
              </label>
              <select
                value={filters.device_name}
                onChange={(e) => handleFilterChange('device_name', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">All Devices</option>
                {computerNames.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </div>

            {/* Source IP */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Source IP
              </label>
              <input
                type="text"
                value={filters.source_ip}
                onChange={(e) => handleFilterChange('source_ip', e.target.value)}
                placeholder="192.168.1.1"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Date Range */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Start Date
              </label>
              <input
                type="datetime-local"
                value={filters.start_date}
                onChange={(e) => handleFilterChange('start_date', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                step="1"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                End Date
              </label>
              <input
                type="datetime-local"
                value={filters.end_date}
                onChange={(e) => handleFilterChange('end_date', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                step="1"
              />
            </div>

            {/* Apply Button */}
            <div>
              <button
                type="submit"
                className="w-full inline-flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <FunnelIcon className="h-4 w-4 mr-2" />
                Apply
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Logs Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Time Generated
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Source
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Description
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {logs.map((log) => (
                    <tr key={log._id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        <div className="flex items-center">
                          <ClockIcon className="h-4 w-4 text-gray-400 mr-2" />
                          {log.TimeGenerated}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(log.Level, log.EventType, log.Status)}`}>
                          {getSeverityLabel(log.Level, log.EventType, log.Status)}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        <div className="flex items-center">
                          <ServerIcon className="h-4 w-4 text-gray-400 mr-2" />
                          {log.ComputerName}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">
                        {log.description}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <Link
                          to={`/logs/${log._id}`}
                          className="inline-flex items-center text-blue-600 hover:text-blue-900"
                        >
                          <EyeIcon className="h-4 w-4 mr-1" />
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {logs.length === 0 && (
              <div className="text-center py-12">
                <ExclamationTriangleIcon className="h-12 w-12 text-gray-300 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No logs found</h3>
                <p className="text-gray-500">Try adjusting your search criteria or filters.</p>
              </div>
            )}

            {/* Pagination */}
            {pagination.totalPages > 1 && (
              <div className="bg-gray-50 px-6 py-3 flex items-center justify-between border-t border-gray-200">
                <div className="flex-1 flex justify-between sm:hidden">
                  <button
                    onClick={() => setPagination(prev => ({ ...prev, page: Math.max(1, prev.page - 1) }))}
                    disabled={pagination.page === 1}
                    className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setPagination(prev => ({ ...prev, page: Math.min(prev.totalPages, prev.page + 1) }))}
                    disabled={pagination.page === pagination.totalPages}
                    className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
                <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm text-gray-700">
                      Showing page <span className="font-medium">{pagination.page}</span> of{' '}
                      <span className="font-medium">{pagination.totalPages}</span>
                    </p>
                  </div>
                  <div>
                    <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                      <button
                        onClick={() => setPagination(prev => ({ ...prev, page: Math.max(1, prev.page - 1) }))}
                        disabled={pagination.page === 1}
                        className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                      >
                        Previous
                      </button>
                      <button
                        onClick={() => setPagination(prev => ({ ...prev, page: Math.min(prev.totalPages, prev.page + 1) }))}
                        disabled={pagination.page === pagination.totalPages}
                        className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                      >
                        Next
                      </button>
                    </nav>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default LogList;