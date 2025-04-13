import React, { useState } from 'react';
import {
  Shield,
  Zap,
  FileWarning,
  AlertCircle,
  Lock,
  ShieldOff,
  Key,
  Fingerprint,
  Bug,
  AlertTriangle,
  Scan,
  Eye,
  EyeOff,
  Code,
  Terminal,
  FileLock,
  FileX,
  FileCode,
  Settings,
  Database,
} from 'lucide-react';
import { motion } from 'framer-motion';
import DragDropUpload from '../components/DragDropUpload';
import FeatureCard from '../components/FeatureCard';

const features = [
  {
    title: 'Real-Time Detection',
    description: 'Instant analysis of files using advanced AI algorithms',
    icon: <Zap className="h-8 w-8 text-amber-600" />,
    gradient: 'from-amber-500/10 to-orange-500/10',
  },
  {
    title: 'Multiple File Types',
    description: 'Support for executables, documents, and scripts',
    icon: <FileWarning className="h-8 w-8 text-amber-600" />,
    gradient: 'from-orange-500/10 to-amber-500/10',
  },
  {
    title: 'Unknown Threat Detection',
    description: 'Identifies new and emerging malware variants',
    icon: <AlertCircle className="h-8 w-8 text-amber-600" />,
    gradient: 'from-amber-500/10 to-orange-500/10',
  },
];

// Subtract 10 from each original x value so icons start farther left
// Row 1 (Top): was 16, 31, 47, 62, 77, 92 => now 6, 21, 37, 52, 67, 82
// Row 2 (Middle): was 16, 31, 47, 62, 77, 92 => now 6, 21, 37, 52, 67, 82
// Row 3 (Bottom): was 20, 40, 60, 80, 95 => now 10, 30, 50, 70, 85
const floatingIcons = [
  // Row 1 (Top row, y ~ 10%)
  { icon: <Shield className="h-24 w-24" />, delay: 0.0,   position: { x: 6,  y: 10 } },
  { icon: <Lock className="h-24 w-24" />, delay: 0.2,     position: { x: 21, y: 10 } },
  { icon: <ShieldOff className="h-24 w-24" />, delay: 0.4, position: { x: 37, y: 10 } },
  { icon: <Key className="h-24 w-24" />, delay: 0.6,       position: { x: 52, y: 10 } },
  { icon: <Fingerprint className="h-24 w-24" />, delay: 0.8, position: { x: 67, y: 10 } },
  { icon: <Bug className="h-24 w-24" />, delay: 1.0,       position: { x: 82, y: 10 } },

  // Row 2 (Middle row, y ~ 50%)
  { icon: <AlertTriangle className="h-24 w-24" />, delay: 1.2, position: { x: 6,  y: 50 } },
  { icon: <Scan className="h-24 w-24" />, delay: 1.4,           position: { x: 21, y: 50 } },
  { icon: <Eye className="h-24 w-24" />, delay: 1.6,            position: { x: 37, y: 50 } },
  { icon: <EyeOff className="h-24 w-24" />, delay: 1.8,         position: { x: 52, y: 50 } },
  { icon: <Code className="h-24 w-24" />, delay: 2.0,           position: { x: 67, y: 50 } },
  { icon: <Terminal className="h-24 w-24" />, delay: 2.2,       position: { x: 82, y: 50 } },

  // Row 3 (Bottom row, y ~ 90%)
  { icon: <FileLock className="h-24 w-24" />, delay: 2.4, position: { x: 10, y: 90 } },
  { icon: <FileX className="h-24 w-24" />, delay: 2.6,    position: { x: 30, y: 90 } },
  { icon: <FileCode className="h-24 w-24" />, delay: 2.8, position: { x: 50, y: 90 } },
  { icon: <Settings className="h-24 w-24" />, delay: 3.0, position: { x: 70, y: 90 } },
  { icon: <Database className="h-24 w-24" />, delay: 3.2, position: { x: 85, y: 90 } },
];

function Home() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleAnalysisStateChange = (analyzing) => {
    setIsAnalyzing(analyzing);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-orange-50/40 via-white to-amber-50/40 relative overflow-hidden">
      {/* Enhanced Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none z-0">
        {/* Animated Gradient Orbs */}
        <motion.div
          className="absolute top-0 left-0 w-[40rem] h-[40rem] bg-gradient-to-br from-orange-500/20 to-amber-500/20 rounded-full blur-3xl opacity-30"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.2, 0.3, 0.2],
            rotate: [0, 45, 0]
          }}
          transition={{
            duration: 10,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        />
        <motion.div
          className="absolute bottom-0 right-0 w-[40rem] h-[40rem] bg-gradient-to-br from-amber-500/20 to-orange-500/20 rounded-full blur-3xl opacity-30"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.2, 0.3, 0.2],
            rotate: [0, -45, 0]
          }}
          transition={{
            duration: 10,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 2,
          }}
        />
        
        {/* Enhanced Floating Icons with Trails */}
        {floatingIcons.map((item, index) => (
          <motion.div
            key={index}
            className="absolute text-amber-600/[0.35]"
            initial={{ y: 0, scale: 1, opacity: 0.35 }}
            animate={{
              y: [0, -20, 0],
              scale: [1, 1.05, 1],
              opacity: [0.35, 0.45, 0.35],
              rotate: [0, 5, 0],
            }}
            transition={{
              duration: 6,
              repeat: Infinity,
              delay: item.delay,
              ease: 'easeInOut',
            }}
            style={{
              left: `${item.position.x}%`,
              top: `${item.position.y}%`,
              transform: 'translate(-50%, -50%)',
            }}
          >
            <motion.div
              className="absolute inset-0 bg-gradient-to-t from-amber-500/10 to-transparent blur-lg"
              animate={{
                height: ['0%', '100%', '0%'],
                opacity: [0, 0.5, 0],
              }}
              transition={{
                duration: 2,
                repeat: Infinity,
                ease: "easeInOut",
                delay: item.delay,
              }}
            />
            {item.icon}
          </motion.div>
        ))}
      </div>

      <div className="max-w-8xl mx-auto px-4 sm:px-6 lg:px-8 py-12 relative z-10">
        {/* Enhanced Hero Section */}
        <motion.div 
          className="text-center mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <motion.div 
            className="flex justify-center items-center mb-12"
            whileHover={{ scale: 1.05 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            <div className="relative">
              <motion.div 
                className="absolute inset-0 bg-gradient-to-r from-orange-500 to-amber-500 rounded-full blur-2xl opacity-20"
                animate={{
                  scale: [1, 1.2, 1],
                  opacity: [0.2, 0.3, 0.2],
                  rotate: [0, 180, 360],
                }}
                transition={{
                  duration: 8,
                  repeat: Infinity,
                  ease: "linear",
                }}
              />
              <div className="relative bg-gradient-to-br from-orange-500 via-amber-500 to-orange-600 p-10 rounded-full shadow-2xl shadow-orange-200/50 overflow-hidden group">
                {/* Shield Icon Background Pattern */}
                <div className="absolute inset-0 opacity-10">
                  <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0zNiAzNGMwIDIuMjEgMS43OSA0IDQgNHM0LTEuNzkgNC00LTEuNzktNC00LTQtNCAxLjc5LTQgNCIgZmlsbD0iI2ZmZiIvPjwvZz48L3N2Zz4=')]" />
                </div>
                
                {/* Animated Shield Icon */}
                <motion.div
                  animate={{
                    scale: [1, 1.1, 1],
                    rotate: [0, 5, 0],
                  }}
                  transition={{
                    duration: 4,
                    repeat: Infinity,
                    ease: "easeInOut",
                  }}
                >
                  <Shield className="h-20 w-20 text-white drop-shadow-lg" strokeWidth={1.5} />
                </motion.div>
                
                {/* Shine Effect */}
                <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/30 to-white/0 opacity-0 group-hover:opacity-100 transition-opacity duration-1000 transform -skew-x-12 translate-x-full group-hover:translate-x-[-200%]" />
              </div>
            </div>
          </motion.div>
          
          {/* Enhanced Title */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="relative"
          >
            <motion.h1 
              className="text-6xl sm:text-7xl font-black text-gray-900 mb-6 relative z-10"
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <span className="relative">
                <span className="absolute -inset-1 bg-gradient-to-r from-orange-600/20 to-amber-600/20 blur-xl" />
                <span className="relative font-extrabold bg-gradient-to-r from-orange-600 via-amber-600 to-orange-600 bg-clip-text text-transparent drop-shadow-sm">
                  MAL
                </span>
              </span>
              <span className="relative ml-2">
                <span className="absolute -inset-1 bg-gradient-to-r from-gray-900/10 to-gray-800/10 blur-xl" />
                <span className="relative text-gray-800">SHIELD</span>
              </span>
            </motion.h1>
          </motion.div>

          {/* Enhanced Description */}
          <motion.p 
            className="text-xl sm:text-2xl text-gray-700 max-w-3xl mx-auto leading-relaxed"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
          >
            Advanced real-time protection against viruses, ransomware, trojans, and unknown threats using cutting-edge machine learning technology.
          </motion.p>
        </motion.div>

        {/* Upload Section with Animation */}
        <motion.div 
          className="relative z-10"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
        >
          <DragDropUpload onAnalysisStateChange={handleAnalysisStateChange} />
        </motion.div>

        {/* Enhanced Features Section with Blur Effect */}
        <motion.div 
          className={`mt-24 grid grid-cols-1 md:grid-cols-3 gap-8 relative z-10 transition-all duration-300 ${
            isAnalyzing ? 'blur-sm pointer-events-none' : ''
          }`}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.8 }}
        >
          {features.map((feature, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.8 + index * 0.2 }}
            >
              <FeatureCard
                title={feature.title}
                description={feature.description}
                icon={feature.icon}
                gradient={feature.gradient}
              />
            </motion.div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}

export default Home;
