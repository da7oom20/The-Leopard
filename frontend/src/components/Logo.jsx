import React from 'react';

// The Leopard - Using canvas.png as-is

export const LeopardLogo = ({ size = 48, className = '' }) => (
  <img
    src="/leopard.png"
    alt="The Leopard"
    width={size}
    height={size}
    className={className}
    style={{ objectFit: 'contain' }}
  />
);

// Compact version for headers
export const LeopardLogoCompact = ({ size = 36, showText = true, className = '' }) => (
  <div className={`flex items-center gap-3 ${className}`}>
    <LeopardLogo size={size} />
    {showText && (
      <span className="text-xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
        The Leopard
      </span>
    )}
  </div>
);

// Full logo with tagline
export const LeopardLogoWithText = ({ size = 48, className = '' }) => (
  <div className={`flex items-center gap-3 ${className}`}>
    <LeopardLogo size={size} />
    <div className="flex flex-col">
      <span className="text-xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
        The Leopard
      </span>
      <span className="text-xs text-zinc-500 -mt-1">Threat Hunter</span>
    </div>
  </div>
);

export const LeopardLogoSilhouette = LeopardLogo;

export default LeopardLogo;
