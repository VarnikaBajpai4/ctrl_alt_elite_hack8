import React from 'react';
import { motion } from 'framer-motion';

function FeatureCard({ icon, title, description, gradient }) {
  return (
    <motion.div 
      className="relative group h-full"
      whileHover={{ scale: 1.02 }}
      transition={{ type: "spring", stiffness: 300 }}
    >
      {/* Enhanced Background Glow */}
      <div className="absolute inset-0 bg-gradient-to-br from-orange-500/10 to-amber-500/10 rounded-2xl blur-xl opacity-30 group-hover:opacity-40 transition-opacity" />
      
      {/* Main Card */}
      <div className="relative h-full bg-gradient-to-br from-white to-white/95 p-8 rounded-2xl shadow-lg border-2 border-amber-200/50 hover:border-amber-300/70 transition-all hover:shadow-2xl hover:shadow-orange-100/30 backdrop-blur-sm overflow-hidden">
        {/* Security Pattern Overlay */}
        <div className="absolute inset-0 opacity-[0.03] group-hover:opacity-[0.05] transition-opacity">
          <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0zNiAzNGMwIDIuMjEgMS43OSA0IDQgNHM0LTEuNzkgNC00LTEuNzktNC00LTQtNCAxLjc5LTQgNCIgZmlsbD0iIzAwMCIvPjwvZz48L3N2Zz4=')]" />
        </div>

        {/* Accent Lines */}
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-orange-500/0 via-amber-500/30 to-orange-500/0" />
        <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-orange-500/0 via-amber-500/30 to-orange-500/0" />
        <div className="absolute left-0 top-0 h-full w-1 bg-gradient-to-b from-orange-500/0 via-amber-500/30 to-orange-500/0" />
        <div className="absolute right-0 top-0 h-full w-1 bg-gradient-to-b from-orange-500/0 via-amber-500/30 to-orange-500/0" />

        {/* Enhanced Icon Container */}
        <div className={`relative ${gradient} w-16 h-16 rounded-xl flex items-center justify-center mb-6 shadow-md group-hover:scale-110 transition-transform overflow-hidden bg-gradient-to-br from-amber-100 to-orange-50`}>
          {/* Icon Background Pattern */}
          <div className="absolute inset-0 opacity-20">
            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMzAiIHZpZXdCb3g9IjAgMCAzMCAzMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0xNSAxNWMwIDIuMjEgMS43OSA0IDQgNHM0LTEuNzkgNC00LTEuNzktNC00LTQtNCAxLjc5LTQgNCIgZmlsbD0iIzAwMCIvPjwvZz48L3N2Zz4=')]" />
          </div>
          
          {/* Enhanced Icon Glow */}
          <div className="absolute inset-0 bg-gradient-to-br from-orange-500/30 to-amber-500/30 opacity-50 group-hover:opacity-100 transition-opacity" />
          
          {/* Icon */}
          <div className="relative z-10 transform group-hover:rotate-3 transition-transform">
            {icon}
          </div>
        </div>

        {/* Enhanced Content */}
        <div className="relative">
          <h3 className="text-xl font-bold text-amber-800 mb-3 group-hover:text-amber-700 transition-colors">{title}</h3>
          <p className="text-gray-700 group-hover:text-gray-800 transition-colors leading-relaxed">{description}</p>
        </div>

        {/* Enhanced Bottom Border Effect */}
        <div className="absolute bottom-0 left-0 right-0 h-1.5 bg-gradient-to-r from-orange-500/0 via-amber-500/70 to-orange-500/0 opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>
    </motion.div>
  );
}

export default FeatureCard;
