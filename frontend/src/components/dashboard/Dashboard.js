import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../services/api';
import { ExclamationTriangleIcon, ShieldExclamationIcon, BoltIcon, HeartIcon, ServerIcon, BellAlertIcon } from '@heroicons/react/24/outline';
import { Doughnut, Line } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Filler } from 'chart.js';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend as RechartsLegend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Filler);

const AGENT_COLORS = [
  '#2563eb', // blue
  '#f59e42', // orange
  '#10b981', // green
  '#ef4444', // red
  '#a78bfa', // purple
  '#fbbf24', // yellow
  '#6366f1', // indigo
  '#14b8a6', // teal
  '#f472b6', // pink
  '#6b7280', // gray
];

const SEVERITY_COLORS = {
  critical: '#ef4444', // red
  high: '#f59e42',    // orange
  moderate: '#fbbf24', // yellow
  low: '#10b981',     // green
};

const MITRE_COLORS = {
  // Persistence techniques
  'T1098': '#ef4444', // red - Account Manipulation
  
  // Credential Access techniques
  'T1110.001': '#f59e42', // orange - Brute Force
  
  // Defense Evasion techniques
  'T1218': '#3b82f6', // blue - Signed Binary Proxy Execution
  
  // Default colors for other techniques
  'default': [
    '#10b981', // green
    '#8b5cf6', // purple
    '#ec4899', // pink
    '#14b8a6', // teal
    '#6366f1', // indigo
    '#fbbf24', // yellow
    '#6b7280', // gray
  ]
};

// Add MITRE technique descriptions
const MITRE_TECHNIQUES = {
  'T1098': 'Account Manipulation',
  'T1110.001': 'Brute Force: Password Guessing',
  'T1218': 'Signed Binary Proxy Execution'
};

// Add dummy IP data
const dummyIpData = [
  { name: "New York", coordinates: [-74.006, 40.7128], value: 156, type: "critical" },
  { name: "London", coordinates: [-0.1276, 51.5074], value: 98, type: "high" },
  { name: "Tokyo", coordinates: [139.6917, 35.6895], value: 143, type: "critical" },
  { name: "Sydney", coordinates: [151.2093, -33.8688], value: 87, type: "high" },
  { name: "Dubai", coordinates: [55.2708, 25.2048], value: 112, type: "critical" },
  { name: "Singapore", coordinates: [103.8198, 1.3521], value: 134, type: "high" },
  { name: "Mumbai", coordinates: [72.8777, 19.0760], value: 76, type: "critical" },
  { name: "São Paulo", coordinates: [-46.6333, -23.5505], value: 92, type: "high" },
  { name: "Cairo", coordinates: [31.2357, 30.0444], value: 65, type: "critical" },
  { name: "Moscow", coordinates: [37.6173, 55.7558], value: 108, type: "high" }
];

// Add WorldMap component
const WorldMap = () => {
  const geoUrl = "/world-110m.json";
  const [position, setPosition] = useState({ coordinates: [0, 0], zoom: 1 });
  const [ipLocations, setIpLocations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCriticalAlerts = async () => {
      try {
        // Fetch latest critical alerts
        const response = await api.get('/logs/analytics/critical-alerts');
        const alerts = response.data;
        console.log("Fetched critical alerts:", alerts);

        // Get unique IPs from alerts
        const uniqueIPs = [...new Set(alerts.map(alert => alert.source_ip).filter(ip => ip))];
        console.log("Unique IPs from alerts:", uniqueIPs);

        // Get locations for each IP
        const locations = await Promise.all(
          uniqueIPs.map(async (ip) => {
            try {
              const response = await api.get(`/logs/analytics/ip-location/${ip}`);
              if (response.data && response.data.latitude && response.data.longitude) {
                // Count occurrences of this IP in alerts
                const count = alerts.filter(alert => alert.source_ip === ip).length;
                return {
                  ip,
                  coordinates: [response.data.longitude, response.data.latitude],
                  count,
                  city: response.data.city,
                  country: response.data.country
                };
              }
              return null;
            } catch (error) {
              console.error(`Error fetching location for IP ${ip}:`, error);
              return null;
            }
          })
        );

        // Filter out null locations and set state
        const validLocations = locations.filter(loc => loc !== null);
        console.log("Valid locations for map:", validLocations);
        setIpLocations(validLocations);
      } catch (error) {
        console.error('Error fetching critical alerts:', error);
        setIpLocations([]);
      } finally {
        setLoading(false);
      }
    };

    fetchCriticalAlerts();
    // Refresh every 5 minutes
    const interval = setInterval(fetchCriticalAlerts, 300000);
    return () => clearInterval(interval);
  }, []);

  function handleZoomIn() {
    if (position.zoom >= 4) return;
    setPosition(pos => ({ ...pos, zoom: pos.zoom * 1.5 }));
  }

  function handleZoomOut() {
    if (position.zoom <= 1) return;
    setPosition(pos => ({ ...pos, zoom: pos.zoom / 1.5 }));
  }

  return (
    <div className="bg-white rounded-lg shadow p-6 ml-auto" style={{ width: '75%' }}>
      <h2 className="text-lg font-bold mb-4 flex items-center">
        <ShieldExclamationIcon className="h-6 w-6 text-red-500 mr-2" />
        Global Security Events Distribution
      </h2>
      <div className="h-[500px] w-full border border-gray-200 rounded-lg overflow-hidden relative">
        <div className="absolute top-4 right-4 z-10 flex flex-col gap-2">
          <button
            onClick={handleZoomIn}
            className="bg-white p-2 rounded-lg shadow-md hover:bg-gray-50 focus:outline-none"
          >
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12h14" />
            </svg>
          </button>
          <button
            onClick={handleZoomOut}
            className="bg-white p-2 rounded-lg shadow-md hover:bg-gray-50 focus:outline-none"
          >
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M5 12h14" />
            </svg>
          </button>
        </div>
        {loading ? (
          <div className="h-full flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          </div>
        ) : (
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{
              scale: 180,
              center: [0, 0]
            }}
            style={{
              width: "100%",
              height: "100%"
            }}
          >
            <ZoomableGroup
              zoom={position.zoom}
              center={position.coordinates}
              minZoom={1}
              maxZoom={4}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map(geo => (
                    <Geography 
                      key={geo.rsmKey} 
                      geography={geo}
                      fill="#EAEAEC"
                      stroke="#D6D6DA"
                      strokeWidth={0.5}
                      style={{
                        default: {
                          outline: "none"
                        },
                        hover: {
                          fill: "#F5F4F6",
                          outline: "none"
                        },
                        pressed: {
                          fill: "#E42",
                          outline: "none"
                        }
                      }}
                    />
                  ))
                }
              </Geographies>
              {ipLocations.map(({ coordinates, count, ip, city, country }) => (
                <Marker key={ip} coordinates={coordinates}>
                  <circle
                    r={Math.sqrt(count) * 2}
                    fill="#FF0000"
                    stroke="#CC0000"
                    strokeWidth={2}
                    style={{
                      cursor: "pointer"
                    }}
                  />
                  <text
                    textAnchor="middle"
                    y={-10}
                    style={{
                      fontFamily: "system-ui",
                      fill: "#5D5A6D",
                      fontSize: "10px"
                    }}
                  >
                    {`${ip} (${count})`}
                  </text>
                  <text
                    textAnchor="middle"
                    y={5}
                    style={{
                      fontFamily: "system-ui",
                      fill: "#5D5A6D",
                      fontSize: "8px"
                    }}
                  >
                    {`${city}, ${country}`}
                  </text>
                </Marker>
              ))}
            </ZoomableGroup>
          </ComposableMap>
        )}
      </div>
    </div>
  );
};

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [agents, setAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [agentsError, setAgentsError] = useState(null);
  const [evolution, setEvolution] = useState([]);
  const [evolutionLoading, setEvolutionLoading] = useState(true);
  const [evolutionError, setEvolutionError] = useState(null);
  const [mitreData, setMitreData] = useState([]);
  const [mitreLoading, setMitreLoading] = useState(true);
  const [mitreError, setMitreError] = useState(null);
  const [osSeverityData, setOsSeverityData] = useState([]);
  const [osSeverityLoading, setOsSeverityLoading] = useState(true);
  const [osSeverityError, setOsSeverityError] = useState(null);
  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [criticalAlertsLoading, setCriticalAlertsLoading] = useState(true);
  const [criticalAlertsError, setCriticalAlertsError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await api.get('/logs/dashboard/stats/');
        setStats(response.data);
      } catch (err) {
        setError('Failed to fetch dashboard stats.');
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  useEffect(() => {
    const fetchAgents = async () => {
      try {
        setAgentsLoading(true);
        setAgentsError(null);
        const response = await api.get('/logs/analytics/alerts-by-agent');
        setAgents(response.data);
      } catch (err) {
        setAgentsError('Failed to fetch agents/devices.');
      } finally {
        setAgentsLoading(false);
      }
    };
    fetchAgents();
  }, []);

  useEffect(() => {
    const fetchEvolution = async () => {
      try {
        setEvolutionLoading(true);
        setEvolutionError(null);
        const response = await api.get('/logs/analytics/alerts-evolution');
        setEvolution(response.data);
      } catch (err) {
        setEvolutionError('Failed to fetch alert evolution data.');
      } finally {
        setEvolutionLoading(false);
      }
    };
    fetchEvolution();
  }, []);

  useEffect(() => {
    const fetchMitreData = async () => {
      try {
        setMitreLoading(true);
        setMitreError(null);
        const response = await api.get('/logs/analytics/mitre-attack');
        setMitreData(response.data);
      } catch (err) {
        setMitreError('Failed to fetch MITRE ATT&CK data.');
      } finally {
        setMitreLoading(false);
      }
    };
    fetchMitreData();
  }, []);

  useEffect(() => {
    const fetchOsSeverityData = async () => {
      try {
        setOsSeverityLoading(true);
        setOsSeverityError(null);
        const response = await api.get('/logs/analytics/os-severity-distribution');
        setOsSeverityData(response.data);
      } catch (err) {
        setOsSeverityError('Failed to fetch OS severity distribution data.');
      } finally {
        setOsSeverityLoading(false);
      }
    };
    fetchOsSeverityData();
  }, []);

  useEffect(() => {
    const fetchCriticalAlerts = async () => {
      try {
        setCriticalAlertsLoading(true);
        setCriticalAlertsError(null);
        const response = await api.get('/logs/analytics/critical-alerts');
        setCriticalAlerts(response.data);
      } catch (err) {
        setCriticalAlertsError('Failed to fetch critical alerts.');
      } finally {
        setCriticalAlertsLoading(false);
      }
    };
    fetchCriticalAlerts();
    // Refresh every 5 minutes
    const interval = setInterval(fetchCriticalAlerts, 300000);
    return () => clearInterval(interval);
  }, []);

  // Prepare data for Doughnut chart
  const doughnutData = {
    labels: agents.slice(0, 10).map((agent) => agent.agent),
    datasets: [
      {
        data: agents.slice(0, 10).map((agent) => agent.count),
        backgroundColor: AGENT_COLORS,
        borderColor: '#fff',
        borderWidth: 2,
      },
    ],
  };

  // Prepare data for Area (Line) chart
  const areaLabels = evolution.map((row) => row.date);
  const areaData = {
    labels: areaLabels,
    datasets: [
      {
        label: 'Critical',
        data: evolution.map((row) => row.critical),
        fill: true,
        backgroundColor: SEVERITY_COLORS.critical + '33',
        borderColor: SEVERITY_COLORS.critical,
        tension: 0.4,
      },
      {
        label: 'High',
        data: evolution.map((row) => row.high),
        fill: true,
        backgroundColor: SEVERITY_COLORS.high + '33',
        borderColor: SEVERITY_COLORS.high,
        tension: 0.4,
      },
      {
        label: 'Moderate',
        data: evolution.map((row) => row.moderate),
        fill: true,
        backgroundColor: SEVERITY_COLORS.moderate + '33',
        borderColor: SEVERITY_COLORS.moderate,
        tension: 0.4,
      },
      {
        label: 'Low',
        data: evolution.map((row) => row.low),
        fill: true,
        backgroundColor: SEVERITY_COLORS.low + '33',
        borderColor: SEVERITY_COLORS.low,
        tension: 0.4,
      },
    ],
  };

  // Add MITRE ATT&CK Doughnut Chart component
  function MitreAttackDoughnutChart({ attackTypes }) {
    const [endAngle, setEndAngle] = useState(0);
    const intervalRef = useRef(null);
    const timeoutRef = useRef(null);

    useEffect(() => {
      setEndAngle(0); // Reset on data change
      let isUnmounted = false;

      function sweep() {
        // Clear any previous interval/timeout
        if (intervalRef.current) clearInterval(intervalRef.current);
        if (timeoutRef.current) clearTimeout(timeoutRef.current);
        setEndAngle(0);
        let angle = 0;
        intervalRef.current = setInterval(() => {
          if (isUnmounted) return;
          angle += 2;
          if (angle >= 360) {
            setEndAngle(360);
            clearInterval(intervalRef.current);
            intervalRef.current = null;
            timeoutRef.current = setTimeout(() => {
              if (!isUnmounted) sweep();
            }, 6000);
          } else {
            setEndAngle(angle);
          }
        }, 30);
      }
      sweep();
      return () => {
        isUnmounted = true;
        if (intervalRef.current) clearInterval(intervalRef.current);
        if (timeoutRef.current) clearTimeout(timeoutRef.current);
      };
    }, [attackTypes]);

    // Filter out any null or invalid techniques and sort by value
    const validTypes = attackTypes.filter(item => 
      item.name && 
      item.name !== 'null' && 
      item.name.match(/^T\d+(\.\d+)?$/)
    ).sort((a, b) => b.value - a.value);

    // Format the data to include descriptions
    const formattedData = validTypes.map(item => ({
      ...item,
      name: `${item.name} - ${MITRE_TECHNIQUES[item.name] || 'Unknown Technique'}`
    }));

    if (formattedData.length === 0) {
      return (
        <div className="text-center py-8 text-gray-500">
          No MITRE ATT&CK techniques detected in the logs.
        </div>
      );
    }

    // Get color for each technique
    const getColor = (techniqueId) => {
      return MITRE_COLORS[techniqueId] || MITRE_COLORS.default[0];
    };

    return (
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={formattedData}
            cx="40%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={2}
            dataKey="value"
            nameKey="name"
            startAngle={-90}
            endAngle={endAngle - 90}
            isAnimationActive={false}
            stroke="none"
          >
            {formattedData.map((entry, index) => {
              const techniqueId = entry.name.split(' - ')[0];
              return (
                <Cell 
                  key={`cell-${index}`} 
                  fill={getColor(techniqueId)}
                  stroke="#fff"
                  strokeWidth={1}
                />
              );
            })}
          </Pie>
          <RechartsTooltip
            contentStyle={{ 
              backgroundColor: '#23272f', 
              color: '#fff', 
              border: '1px solid #444',
              borderRadius: '4px',
              padding: '8px'
            }}
            formatter={(value, name) => [`${value} events`, name]}
          />
          <RechartsLegend
            layout="vertical"
            align="right"
            verticalAlign="middle"
            wrapperStyle={{ 
              color: '#fff',
              paddingLeft: '10px',
              width: '45%',
              marginLeft: '-5%'
            }}
            formatter={(value) => (
              <span style={{ 
                display: 'inline-block',
                marginLeft: '8px',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                maxWidth: '200px'
              }}>
                {value}
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    );
  }

  // Function to render severity dot
  const renderSeverityDot = (level) => {
    const color = level >= 13 ? 'bg-red-500' : 'bg-yellow-500';
    return (
      <span className={`inline-block w-2 h-2 rounded-full ${color} mr-2`}></span>
    );
  };

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-bold text-gray-900 mb-4">Dashboard</h1>
      {loading ? (
        <div className="text-center py-12">Loading dashboard...</div>
      ) : error ? (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">{error}</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Total Security Events */}
          <div className="bg-white rounded-lg shadow p-6 flex flex-col items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-blue-500 mb-2" />
            <div className="text-3xl font-bold text-gray-900 mb-1">{stats?.total_events?.toLocaleString() ?? 0}</div>
            <div className="text-gray-500 text-sm">Total Security Events</div>
          </div>
          {/* Critical Alerts */}
          <div className="bg-white rounded-lg shadow p-6 flex flex-col items-center">
            <ShieldExclamationIcon className="h-8 w-8 text-red-500 mb-2" />
            <div className="text-3xl font-bold text-gray-900 mb-1">{stats?.critical_alerts ?? 0}</div>
            <div className="text-gray-500 text-sm">Critical Alerts</div>
          </div>
          {/* Active Threats */}
          <div className="bg-white rounded-lg shadow p-6 flex flex-col items-center">
            <BoltIcon className="h-8 w-8 text-yellow-500 mb-2" />
            <div className="text-3xl font-bold text-gray-900 mb-1">{stats?.active_threats ?? 0}</div>
            <div className="text-gray-500 text-sm">Active Threats</div>
          </div>
          {/* System Health */}
          <div className="bg-white rounded-lg shadow p-6 flex flex-col items-center">
            <HeartIcon className="h-8 w-8 text-green-500 mb-2" />
            <div className="text-3xl font-bold text-gray-900 mb-1">{stats?.system_health ?? 0}%</div>
            <div className="text-gray-500 text-sm">System Health</div>
          </div>
        </div>
      )}

      {/* Flex row for Doughnut and Area Chart */}
      <div className="flex flex-col md:flex-row gap-8 mt-8">
        {/* Doughnut Chart (left) */}
        <div className="bg-white rounded-lg shadow p-6 flex-1 max-w-md mx-auto md:mx-0 md:w-1/2 flex flex-col items-center justify-center">
          <h2 className="text-lg font-bold mb-4 flex items-center">
            <ServerIcon className="h-6 w-6 text-blue-500 mr-2" />
            Top Agents / Devices
          </h2>
          {agentsLoading ? (
            <div className="text-center py-8">Loading agents/devices...</div>
          ) : agentsError ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">{agentsError}</div>
          ) : agents.length === 0 ? (
            <div className="text-center py-8 text-gray-500">No agent/device data available.</div>
          ) : (
            <>
              <div className="w-full max-w-xs" style={{ height: 200 }}>
                <Doughnut data={doughnutData} options={{ plugins: { legend: { display: false } }, maintainAspectRatio: false }} height={200} />
              </div>
              <div className="mt-6 w-full max-w-xs">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Agent / Device</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Log Count</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {agents.slice(0, 10).map((agent, idx) => (
                      <tr key={agent.agent}>
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-900 flex items-center">
                          <span className="inline-block w-3 h-3 rounded-full mr-2" style={{ backgroundColor: AGENT_COLORS[idx % AGENT_COLORS.length] }}></span>
                          {agent.agent}
                        </td>
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-900">{agent.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
        {/* Area Chart (right) */}
        <div className="bg-white rounded-lg shadow p-6 flex-1 md:w-1/2 flex flex-col items-center justify-center">
          <h2 className="text-lg font-bold mb-4 flex items-center">
            <ShieldExclamationIcon className="h-6 w-6 text-red-500 mr-2" />
            Alert Evolution by Severity
          </h2>
          {evolutionLoading ? (
            <div className="text-center py-8">Loading alert evolution...</div>
          ) : evolutionError ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">{evolutionError}</div>
          ) : evolution.length === 0 ? (
            <div className="text-center py-8 text-gray-500">No alert evolution data available.</div>
          ) : (
            <div className="w-full" style={{ height: '400px' }}>
              <Line
                data={areaData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: { 
                    legend: { 
                      position: 'bottom',
                      labels: {
                        boxWidth: 12,
                        padding: 15
                      }
                    } 
                  },
                  scales: {
                    y: { 
                      beginAtZero: true, 
                      title: { 
                        display: true, 
                        text: 'Count',
                        font: {
                          size: 14,
                          weight: 'bold'
                        }
                      },
                      ticks: {
                        font: {
                          size: 12
                        }
                      }
                    },
                    x: { 
                      title: { 
                        display: true, 
                        text: 'Date',
                        font: {
                          size: 14,
                          weight: 'bold'
                        }
                      },
                      ticks: {
                        font: {
                          size: 12
                        }
                      }
                    },
                  },
                }}
              />
            </div>
          )}
        </div>
      </div>

      {/* MITRE ATT&CK and OS Severity Distribution Charts */}
      <div className="flex flex-col md:flex-row gap-8 mt-8">
        {/* MITRE ATT&CK Chart (left) */}
        <div className="bg-white rounded-lg shadow p-6 flex-1">
          <h2 className="text-lg font-bold mb-4 flex items-center">
            <ShieldExclamationIcon className="h-6 w-6 text-red-500 mr-2" />
            MITRE ATT&CK Distribution
          </h2>
          {mitreLoading ? (
            <div className="text-center py-8">Loading MITRE ATT&CK data...</div>
          ) : mitreError ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">{mitreError}</div>
          ) : mitreData.length === 0 ? (
            <div className="text-center py-8 text-gray-500">No MITRE ATT&CK data available.</div>
          ) : (
            <MitreAttackDoughnutChart attackTypes={mitreData} />
          )}
        </div>

        {/* OS Severity Distribution Chart (right) */}
        <div className="bg-white rounded-lg shadow p-6 flex-1">
          <h2 className="text-lg font-bold mb-4 flex items-center">
            <ServerIcon className="h-6 w-6 text-blue-500 mr-2" />
            OS Severity Distribution
          </h2>
          {osSeverityLoading ? (
            <div className="text-center py-8">Loading OS severity data...</div>
          ) : osSeverityError ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">{osSeverityError}</div>
          ) : osSeverityData.length === 0 ? (
            <div className="text-center py-8 text-gray-500">No OS severity data available.</div>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={osSeverityData}
                margin={{
                  top: 20,
                  right: 30,
                  left: 20,
                  bottom: 5,
                }}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="os" 
                  angle={-45}
                  textAnchor="end"
                  height={100}
                  interval={0}
                  tick={{ fontSize: 12 }}
                />
                <YAxis />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#23272f',
                    color: '#fff',
                    border: '1px solid #444',
                    borderRadius: '4px',
                    padding: '8px'
                  }}
                />
                <Legend />
                <Bar dataKey="critical" name="Critical" stackId="a" fill={SEVERITY_COLORS.critical} />
                <Bar dataKey="high" name="High" stackId="a" fill={SEVERITY_COLORS.high} />
                <Bar dataKey="moderate" name="Moderate" stackId="a" fill={SEVERITY_COLORS.moderate} />
                <Bar dataKey="low" name="Low" stackId="a" fill={SEVERITY_COLORS.low} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* World Map */}
      <WorldMap />

      {/* Critical Alerts Section */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-800">Critical Alerts</h2>
          <span className="text-sm text-gray-500">Latest Alerts</span>
        </div>
        {criticalAlertsLoading ? (
          <div className="flex justify-center items-center h-32">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          </div>
        ) : criticalAlertsError ? (
          <div className="text-red-500 text-center p-4">{criticalAlertsError}</div>
        ) : criticalAlerts.length === 0 ? (
          <div className="text-gray-500 text-center p-4">No critical alerts found</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Machine Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {criticalAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{alert.timestamp}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{alert.source}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{alert.type}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <button
                        onClick={() => navigate(`/logs/${alert.id}`)}
                        className="inline-flex items-center px-3 py-1 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;