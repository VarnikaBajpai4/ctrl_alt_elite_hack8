import React, { useState, useCallback } from 'react';
import { Upload, FileWarning, CheckCircle, AlertCircle, X, Shield } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import AnalysisResults from './AnalysisResults';

const allowedTypes = [
  'application/x-msdownload', // .exe
  'application/x-executable', // .elf
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel.sheet.macroEnabled.12', // .xlsm
  'text/javascript',
  'text/x-python',
  'text/x-sh',
  'application/zip', // .zip
  'application/x-zip-compressed' // .zip alternative MIME type
];

const maxSize = 100 * 1024 * 1024; // 100MB
const maxFiles = 50; // Maximum number of files allowed

function DragDropUpload({ onAnalysisStateChange }) {
  const [isDragging, setIsDragging] = useState(false);
  const [files, setFiles] = useState([]);
  const [error, setError] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResults, setAnalysisResults] = useState(null);
  const [analysisErrors, setAnalysisErrors] = useState([]);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setIsDragging(true);
    } else if (e.type === 'dragleave') {
      setIsDragging(false);
    }
  }, []);

  const validateFile = (file) => {
    // Check if file is an ELF file by extension
    const isElfFile = file.name.toLowerCase().endsWith('.elf');
    
    // If it's an ELF file, allow it regardless of MIME type
    if (isElfFile) {
      if (file.size > maxSize) {
        setError('File size exceeds 100MB limit.');
        return false;
      }
      return true;
    }

    // For non-ELF files, check MIME type
    if (!allowedTypes.includes(file.type)) {
      setError('Invalid file type. Please upload executable, document, or script files.');
      return false;
    }
    if (file.size > maxSize) {
      setError('File size exceeds 100MB limit.');
      return false;
    }
    return true;
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    setError(null);

    const droppedFiles = Array.from(e.dataTransfer.files);
    
    // Check if adding these files would exceed the maximum limit
    if (files.length + droppedFiles.length > maxFiles) {
      setError(`Maximum ${maxFiles} files allowed. You can only add ${maxFiles - files.length} more files.`);
      return;
    }
    
    const validFiles = droppedFiles.filter(validateFile);
    
    if (validFiles.length > 0) {
      setFiles(prevFiles => [...prevFiles, ...validFiles]);
    }
  }, [files.length]);

  const handleFileInput = (e) => {
    setError(null);
    const selectedFiles = Array.from(e.target.files);
    
    // Check if adding these files would exceed the maximum limit
    if (files.length + selectedFiles.length > maxFiles) {
      setError(`Maximum ${maxFiles} files allowed. You can only add ${maxFiles - files.length} more files.`);
      return;
    }
    
    const validFiles = selectedFiles.filter(validateFile);
    
    if (validFiles.length > 0) {
      setFiles(prevFiles => [...prevFiles, ...validFiles]);
    }
  };

  const handleCancel = () => {
    setFiles([]);
    setUploadProgress(0);
    setIsUploading(false);
  };

  const simulateUpload = () => {
    setIsUploading(true);
    setUploadProgress(0);
    
    const interval = setInterval(() => {
      setUploadProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsUploading(false);
          return 100;
        }
        return prev + 10;
      });
    }, 500);
  };

  const handleAnalysis = async () => {
    try {
      setIsAnalyzing(true);
      onAnalysisStateChange?.(true);
      setAnalysisResults(null);
      setAnalysisErrors([]);

      // Validate files before sending
      if (!files || files.length === 0) {
        throw new Error("No files selected for analysis");
      }

      const formData = new FormData();
      files.forEach((file, index) => {
        if (!(file instanceof File)) {
          throw new Error(`Invalid file at index ${index}`);
        }
        formData.append('files', file, file.name);
      });

      const response = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        body: formData,
        headers: {
          // Don't set Content-Type header - let the browser set it with the boundary
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `Analysis failed: ${response.statusText}`);
      }

      const data = await response.json();
      setAnalysisResults(data.results);
      setAnalysisErrors(data.errors);
    } catch (error) {
      console.error('Analysis error:', error);
      setAnalysisErrors([error.message]);
    } finally {
      setIsAnalyzing(false);
      onAnalysisStateChange?.(false);
    }
  };

  return (
    <>
      <div className="max-w-2xl mx-auto">
        <motion.div
          className={`relative border-2 border-dashed rounded-2xl p-12 transition-all ${
            isDragging
              ? 'border-amber-500 bg-gradient-to-br from-amber-50/80 to-orange-50/80'
              : 'border-amber-200 bg-gradient-to-br from-white/95 to-white/90 hover:border-amber-400/70'
          } shadow-2xl shadow-orange-100/30 backdrop-blur-sm`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 300 }}
        >
          {/* Background Effects */}
          <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-amber-500/5 rounded-2xl" />
          <div 
            className="absolute inset-0" 
            style={{
              backgroundImage: "url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0zNiAzNGMwIDIuMjEgMS43OSA0IDQgNHM0LTEuNzkgNC00LTEuNzktNC00LTQtNCAxLjc5LTQgNCIgZmlsbD0iIzAwMCIvPjwvZz48L3N2Zz4=')",
              opacity: 0.03
            }}
          />
          
          {/* Accent Lines */}
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-orange-500/0 via-amber-500/30 to-orange-500/0" />
          <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-orange-500/0 via-amber-500/30 to-orange-500/0" />
          <div className="absolute left-0 top-0 h-full w-1 bg-gradient-to-b from-orange-500/0 via-amber-500/30 to-orange-500/0" />
          <div className="absolute right-0 top-0 h-full w-1 bg-gradient-to-b from-orange-500/0 via-amber-500/30 to-orange-500/0" />

          <input
            type="file"
            multiple
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-20"
            onChange={handleFileInput}
            accept=".exe,.elf,.pdf,.doc,.docx,.xls,.xlsx,.xlsm,.js,.py,.sh,.zip"
          />
          
          <div className="relative z-10">
            <motion.div 
              className="text-center"
              initial={false}
              animate={isDragging ? { scale: 1.05 } : { scale: 1 }}
            >
              <motion.div 
                className={`mx-auto h-24 w-24 rounded-2xl flex items-center justify-center bg-gradient-to-br ${
                  isDragging ? 'from-amber-100 to-orange-50' : 'from-gray-50/80 to-white/80'
                } mb-6 shadow-lg relative overflow-hidden group`}
                whileHover={{ scale: 1.05 }}
              >
                {/* Icon Background Pattern */}
                <div className="absolute inset-0 opacity-10">
                  <div 
                    className="absolute inset-0"
                    style={{
                      backgroundImage: "url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMzAiIHZpZXdCb3g9IjAgMCAzMCAzMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0xNSAxNWMwIDIuMjEgMS43OSA0IDQgNHM0LTEuNzkgNC00LTEuNzktNC00LTQtNCAxLjc5LTQgNCIgZmlsbD0iIzAwMCIvPjwvZz48L3N2Zz4=')"
                    }}
                  />
                </div>
                
                <motion.div
                  animate={{
                    y: isDragging ? [0, -8, 0] : 0
                  }}
                  transition={{
                    duration: 1.5,
                    repeat: isDragging ? Infinity : 0,
                    ease: "easeInOut"
                  }}
                >
                  <Upload className={`h-12 w-12 ${isDragging ? 'text-amber-600' : 'text-amber-500/80'} transition-colors`} />
                </motion.div>
              </motion.div>
              <motion.div
                initial={false}
                animate={isDragging ? { scale: 1.02 } : { scale: 1 }}
              >
                <h3 className="text-2xl font-bold text-amber-800 mb-3">
                  {isDragging ? 'Release to Upload' : 'Drop your files here'}
                </h3>
                <p className="text-base text-gray-600 mb-2">
                  or click to browse from your computer
                </p>
                <p className="text-sm text-amber-600/80">
                  Supports up to {maxFiles} files (executables, documents, and scripts) up to 100MB each
                </p>
                {files.length > 0 && (
                  <motion.p 
                    className="mt-2 text-sm font-medium text-amber-600"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                  >
                    {files.length} file{files.length !== 1 ? 's' : ''} selected ({maxFiles - files.length} remaining)
                  </motion.p>
                )}
              </motion.div>
            </motion.div>
          </div>
        </motion.div>

        {/* Selected Files */}
        <AnimatePresence>
          {files.length > 0 && (
            <motion.div 
              className="mt-6 space-y-4"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              {files.map((file, index) => (
                <motion.div
                  key={index}
                  className="flex items-center justify-between p-4 bg-gradient-to-br from-white to-amber-50/50 rounded-xl border-2 border-amber-100/50 shadow-lg backdrop-blur-sm"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ delay: index * 0.1 }}
                >
                  <div className="flex items-center">
                    <div className="p-2 bg-amber-100/50 rounded-lg mr-3">
                      <FileWarning className="h-5 w-5 text-amber-600" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-amber-900">{file.name}</p>
                      <p className="text-xs text-amber-600/80">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                    </div>
                  </div>
                  <motion.button
                    whileHover={{ scale: 1.1, rotate: 90 }}
                    whileTap={{ scale: 0.9 }}
                    onClick={() => setFiles(files.filter((_, i) => i !== index))}
                    className="p-2 hover:bg-red-100/50 rounded-full text-red-500 transition-colors"
                  >
                    <X className="h-4 w-4" />
                  </motion.button>
                </motion.div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error Message */}
        <AnimatePresence>
          {error && (
            <motion.div 
              className="mt-4 p-6 bg-red-50/90 rounded-xl border-2 border-red-200 shadow-lg backdrop-blur-sm"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <div className="flex items-center">
                <AlertCircle className="h-5 w-5 text-red-500 mr-2" />
                <span className="text-sm font-medium text-red-700">{error}</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Enhanced CTA Button */}
        <motion.button
          onClick={handleAnalysis}
          className={`mt-8 w-full py-6 px-8 rounded-xl text-white font-medium transition-all shadow-xl relative overflow-hidden ${
            files.length > 0 && !isAnalyzing
              ? 'bg-gradient-to-r from-orange-600 via-amber-600 to-orange-600 hover:from-orange-700 hover:via-amber-700 hover:to-orange-700 shadow-orange-100/50'
              : 'bg-gradient-to-r from-orange-600/50 via-amber-600/50 to-orange-600/50 cursor-not-allowed'
          }`}
          disabled={files.length === 0 || isAnalyzing}
          whileHover={files.length > 0 && !isAnalyzing ? { scale: 1.02 } : {}}
          whileTap={files.length > 0 && !isAnalyzing ? { scale: 0.98 } : {}}
        >
          <div className="absolute inset-0 bg-gradient-to-r from-orange-600/0 via-white/10 to-orange-600/0 opacity-0 hover:opacity-100 transition-opacity" />
          <div className="relative flex items-center justify-center">
            <Shield className="h-6 w-6 mr-3" />
            <span className="text-lg">
              {isAnalyzing ? 'Analyzing Files...' : `Analyze ${files.length} File${files.length !== 1 ? 's' : ''} for Malware`}
            </span>
          </div>
        </motion.button>
      </div>

      <AnalysisResults 
        isLoading={isAnalyzing}
        results={analysisResults}
        errors={analysisErrors}
      />
    </>
  );
}

export default DragDropUpload;
