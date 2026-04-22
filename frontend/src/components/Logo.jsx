import React from 'react';

/**
 * The Leopard — wordmark and marks.
 *
 * The visual signature is the serif wordmark itself: italic Fraunces "Leopard"
 * with a hairline rule beneath. The .png mark is kept available for surfaces
 * that need a literal logo (login hero, favicon-adjacent contexts).
 */

export const LeopardMark = ({ size = 48, className = '' }) => (
  <img
    src="/leopard.png"
    alt="The Leopard"
    width={size}
    height={size}
    className={className}
    style={{ objectFit: 'contain', filter: 'grayscale(0.15) contrast(1.05)' }}
  />
);

// Backwards-compatible aliases — all surfaces import from these names.
export const LeopardLogo = LeopardMark;
export const LeopardLogoSilhouette = LeopardMark;

/**
 * Editorial wordmark — the canonical brand expression.
 * Use as the primary "logo" on headers and login.
 */
export const LeopardLogoCompact = ({ size = 36, showText = true, className = '' }) => (
  <div className={`flex items-center gap-3 ${className}`}>
    <LeopardMark size={size} />
    {showText && (
      <span className="flex flex-col leading-none">
        <span className="font-serif italic text-2xl tracking-tight wordmark-gradient" style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
          Leopard
        </span>
        <span className="eyebrow mt-1.5">Field Manual · v5</span>
      </span>
    )}
  </div>
);

/**
 * Wordmark with tagline — used in larger hero contexts.
 */
export const LeopardLogoWithText = ({ size = 48, className = '' }) => (
  <div className={`flex items-center gap-4 ${className}`}>
    <LeopardMark size={size} />
    <div className="flex flex-col leading-none">
      <span className="font-serif italic text-3xl tracking-tight wordmark-gradient" style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
        The Leopard
      </span>
      <span className="eyebrow mt-2">Threat Intelligence · Field Manual</span>
    </div>
  </div>
);

export default LeopardMark;
