import { useEffect, useRef, useState } from 'react';

// Smoothly animate a number toward a target — used for the risk score so it
// "climbs" rather than snapping, which is the whole point of the live monitor.
// displayRef tracks the currently-shown value so a new target mid-animation
// continues from where the needle actually is.
export function useCountUp(target, durationMs = 700) {
  const [value, setValue] = useState(target);
  const displayRef = useRef(target);
  const rafRef = useRef(0);

  useEffect(() => {
    const from = displayRef.current;
    const delta = target - from;
    if (Math.abs(delta) < 0.5) {
      displayRef.current = target;
      setValue(target);
      return;
    }
    let start;
    const tick = (ts) => {
      if (start === undefined) start = ts;
      const t = Math.min(1, (ts - start) / durationMs);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      const current = from + delta * eased;
      displayRef.current = current;
      setValue(current);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        displayRef.current = target;
        setValue(target);
      }
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, durationMs]);

  return value;
}
