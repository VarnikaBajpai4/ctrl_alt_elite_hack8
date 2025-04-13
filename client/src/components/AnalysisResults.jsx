import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileWarning,
  AlertCircle,
  Shield,
  FileCode,
  FileSpreadsheet,
  FileText,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
} from 'lucide-react';

const LoadingScreen = () => (
  <motion.div 
    className="fixed inset-0 bg-gradient-to-br from-orange-50/95 via-white/95 to-amber-50/95 backdrop-blur-sm z-50 flex items-center justify-center"
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
  >
    <motion.div 
      className="text-center"
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ delay: 0.2 }}
    >
      <motion.div 
        className="w-24 h-24 rounded-2xl bg-gradient-to-br from-amber-100 to-orange-50 mx-auto mb-8 flex items-center justify-center relative overflow-hidden shadow-xl"
        animate={{ 
          scale: [1, 1.05, 1],
          rotate: [0, 5, 0]
        }}
        transition={{ 
          duration: 2,
          repeat: Infinity,
          ease: "easeInOut"
        }}
      >
        <motion.div
          className="absolute inset-0 bg-gradient-to-br from-orange-500/20 to-amber-500/20 opacity-50"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.2, 0.3, 0.2],
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        />
        <Loader2 className="w-12 h-12 text-amber-600 animate-spin" />
      </motion.div>
      <h3 className="text-2xl font-bold text-amber-800 mb-3">Analyzing Files</h3>
      <p className="text-gray-600">Please wait while we scan your files for potential threats...</p>
    </motion.div>
  </motion.div>
);

const FileTypeIcon = ({ type }) => {
  switch (type) {
    case 'executable':
      return <FileCode className="h-6 w-6" />;
    case 'elf':
      return <FileCode className="h-6 w-6" />;
    case 'doc':
    case 'docx':
    case 'rtf document':
      return <FileText className="h-6 w-6" />;
    case 'xlsm':
    case 'xlsx':
      return <FileSpreadsheet className="h-6 w-6" />;
    default:
      return <FileWarning className="h-6 w-6" />;
  }
};

const SeverityBadge = ({ probability }) => {
  let color;
  let text;
  
  if (probability >= 0.7) {
    color = 'bg-red-100 text-red-700 border-red-200';
    text = 'High Risk';
  } else if (probability >= 0.3) {
    color = 'bg-yellow-100 text-yellow-700 border-yellow-200';
    text = 'Medium Risk';
  } else {
    color = 'bg-green-100 text-green-700 border-green-200';
    text = 'Low Risk';
  }

  return (
    <span className={`px-3 py-1 rounded-full text-sm font-medium ${color} border`}>
      {text}
    </span>
  );
};

const ResultCard = ({ result }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const renderExecutableContent = () => (
    <div className="space-y-4">
      <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
        <h4 className="text-lg font-semibold text-gray-800 mb-2">EMBER Analysis</h4>
        <p className="text-gray-700">
          <span className="font-medium">Malware Probability:</span> {(result.ember_probability * 100).toFixed(2)}%
        </p>
        {result.important_features && (
          <div className="mt-3">
            <h5 className="font-medium text-gray-800 mb-2">Key Indicators</h5>
            <ul className="list-disc list-inside text-sm text-gray-600">
              {result.important_features.map((feature, idx) => (
                <li key={idx}>{feature}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {result.malware_categorization?.length > 0 && (
        <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
          <h4 className="text-lg font-semibold text-gray-800 mb-2">Malware Classification</h4>
          {result.malware_categorization.map((cat, idx) => (
            <div key={idx} className="mb-3 last:mb-0">
              <p className="font-medium text-amber-900">{cat.family}</p>
              <p className="text-sm text-gray-600">{cat.rationale}</p>
              <div className="mt-1">
                <span className="text-sm font-medium text-amber-600">
                  Confidence: {cat.probability}%
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {result.yara_matches?.filter(match => match.severity !== 'low').length > 0 && (
        <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
          <h4 className="text-lg font-semibold text-gray-800 mb-2">YARA Rule Matches</h4>
          {result.yara_matches
            .filter(match => match.severity !== 'low')
            .map((match, idx) => (
              <div key={idx} className="mb-3 last:mb-0">
                <p className="font-medium text-amber-900">{match.rule}</p>
                <p className="text-sm text-gray-600">{match.description}</p>
                <span className="text-sm font-medium text-amber-600">
                  Severity: {match.severity}
                </span>
              </div>
            ))}
        </div>
      )}
    </div>
  );

  const renderDocumentContent = () => (
    <div className="space-y-4">
      {result.document_analysis?.yara_matches?.filter(match => match.severity !== 'low').length > 0 && (
        <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
          <h4 className="text-lg font-semibold text-gray-800 mb-2">YARA Rule Matches</h4>
          {result.document_analysis.yara_matches
            .filter(match => match.severity !== 'low')
            .map((match, idx) => (
              <div key={idx} className="mb-3 last:mb-0">
                <p className="font-medium text-amber-900">{match.rule}</p>
                <p className="text-sm text-gray-600">{match.description}</p>
                <span className="text-sm font-medium text-amber-600">
                  Severity: {match.severity}
                </span>
              </div>
            ))}
        </div>
      )}

      {result.document_analysis?.gemini_analysis && (
        <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
          <h4 className="text-lg font-semibold text-gray-800 mb-2">AI Analysis</h4>
          <p className="text-sm text-gray-600 mb-3">{result.document_analysis.gemini_analysis.description}</p>
          {result.document_analysis.gemini_analysis.suspicious_indicators?.length > 0 && (
            <div className="mt-3">
              <h5 className="font-medium text-gray-800 mb-2">Suspicious Indicators</h5>
              <ul className="list-disc list-inside text-sm text-gray-600">
                {result.document_analysis.gemini_analysis.suspicious_indicators.map((indicator, idx) => (
                  <li key={idx}>{indicator}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {result.document_analysis?.macros?.vba_macros?.length > 0 && (
        <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-100">
          <h4 className="text-lg font-semibold text-yellow-800 mb-2">Macro Analysis</h4>
          <p className="text-yellow-700 mb-3">
            Document contains {result.document_analysis.macros.vba_macros.length} VBA macros
          </p>
          {result.document_analysis.macros.suspicious_keywords?.length > 0 && (
            <div className="mt-2">
              <h5 className="font-medium text-yellow-800 mb-1">Suspicious Keywords Found</h5>
              <div className="flex flex-wrap gap-2">
                {result.document_analysis.macros.suspicious_keywords.map((keyword, idx) => (
                  <span key={idx} className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-sm">
                    {keyword}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {result.document_analysis?.embedded_files?.extracted_files?.length > 0 && (
        <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
          <h4 className="text-lg font-semibold text-gray-800 mb-2">Embedded Files</h4>
          <p className="text-sm text-gray-600 mb-2">
            Found {result.document_analysis.embedded_files.extracted_files.length} embedded files
          </p>
          <ul className="list-disc list-inside text-sm text-gray-600">
            {result.document_analysis.embedded_files.extracted_files.map((file, idx) => (
              <li key={idx}>
                {file.name} ({Math.round(file.size / 1024)} KB)
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );

  const renderELFContent = () => (
    <div className="space-y-4">
      <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
        <h4 className="text-lg font-semibold text-gray-800 mb-2">Model Predictions</h4>
        <p className="text-gray-700">
          <span className="font-medium">Malware Probability:</span> {(result.ember_probability * 100).toFixed(2)}%
        </p>
      </div>

      {result.important_imports && (
        <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
          <h4 className="text-lg font-semibold text-gray-800 mb-2">Critical Imports</h4>
          <ul className="list-disc list-inside text-sm text-gray-600">
            {result.important_imports.map((imp, idx) => (
              <li key={idx}>{imp}</li>
            ))}
          </ul>
        </div>
      )}

      {result.yara_matches?.filter(match => match.severity !== 'low').length > 0 && (
        <div className="bg-white/50 p-4 rounded-lg border border-amber-100">
          <h4 className="text-lg font-semibold text-gray-800 mb-2">YARA Rule Matches</h4>
          {result.yara_matches
            .filter(match => match.severity !== 'low')
            .map((match, idx) => (
              <div key={idx} className="mb-3 last:mb-0">
                <p className="font-medium text-amber-900">{match.rule}</p>
                <p className="text-sm text-gray-600">{match.description}</p>
                <span className="text-sm font-medium text-amber-600">
                  Severity: {match.severity}
                </span>
              </div>
            ))}
        </div>
      )}
    </div>
  );

  const renderContent = () => {
    // Check if it's a document type first
    if (result.type?.includes('document') || 
        result.type === 'docx' || 
        result.type === 'doc' ||
        result.type === 'xlsx' || 
        result.type === 'xlsm' || 
        result.type === 'pdf') {
      return renderDocumentContent();
    }
    
    // Then check for other types
    switch (result.type) {
      case 'executable':
        return renderExecutableContent();
      case 'elf':
        return renderELFContent();
      default:
        return (
          <div className="text-gray-600">
            Unknown file type analysis
          </div>
        );
    }
  };

  return (
    <motion.div 
      className="bg-gradient-to-br from-white to-amber-50/30 rounded-xl border-2 border-amber-100/50 p-6 shadow-lg backdrop-blur-sm"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-amber-100/50 rounded-lg">
            <FileTypeIcon type={result.type} />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              {result.type.charAt(0).toUpperCase() + result.type.slice(1)} Analysis
            </h3>
            <p className="text-sm text-gray-600">
              {result.type === 'executable' || result.type === 'elf' 
                ? `Risk Score: ${(result.ember_probability * 100).toFixed(2)}%`
                : `Confidence Score: ${(result.document_analysis?.gemini_analysis?.confidence_score * 100 || 0).toFixed(0)}%`
              }
            </p>
          </div>
        </div>
        <SeverityBadge 
          probability={result.type === 'executable' || result.type === 'elf' 
            ? result.ember_probability
            : result.document_analysis?.gemini_analysis?.confidence_score || 0
          } 
        />
      </div>

      {renderContent()}

      <motion.button
        className="mt-4 text-sm font-medium text-amber-600 hover:text-amber-700 focus:outline-none"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        {isExpanded ? 'Show Less' : 'Show More'}
      </motion.button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="mt-4 overflow-hidden"
          >
            <pre className="bg-gray-50 p-4 rounded-lg text-xs overflow-x-auto">
              {JSON.stringify(result, null, 2)}
            </pre>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

const AnalysisResults = ({ isLoading, results, errors }) => {
  return (
    <>
      <AnimatePresence>
        {isLoading && <LoadingScreen />}
      </AnimatePresence>

      {!isLoading && (results?.length > 0 || errors?.length > 0) && (
        <motion.div 
          className="max-w-4xl mx-auto py-8 px-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.4 }}
        >
          {errors?.length > 0 && (
            <motion.div 
              className="mb-6 bg-red-50 border-2 border-red-100 rounded-xl p-4"
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <div className="flex items-center mb-2">
                <AlertCircle className="h-5 w-5 text-red-500 mr-2" />
                <h3 className="text-lg font-semibold text-red-700">Analysis Errors</h3>
              </div>
              <ul className="list-disc list-inside text-red-600 text-sm">
                {errors.map((error, idx) => (
                  <li key={idx}>{error}</li>
                ))}
              </ul>
            </motion.div>
          )}

          <div className="space-y-6">
            {results?.map((result, idx) => (
              <ResultCard key={idx} result={result} />
            ))}
          </div>
        </motion.div>
      )}
    </>
  );
};

export default AnalysisResults; 