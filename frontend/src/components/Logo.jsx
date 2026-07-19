// AntiScam AI logo mark: a shield (protection) with a live signal pulse inside
// (intercepting a call in real time). Rendered white, to sit on the gradient
// brand badge. Kept as a component so the same mark can be reused anywhere.

export function LogoMark({ size = 22 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3 L19 5.8 V12.6 C19 16.4 16 19.3 12 20.9 C8 19.3 5 16.4 5 12.6 V5.8 Z"
        fill="rgba(255,255,255,0.16)"
        stroke="#fff"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M7.2 12.3 H9.4 L10.7 8.9 L12.5 15.2 L13.8 11.4 L15 12.3 H16.9"
        fill="none"
        stroke="#fff"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
