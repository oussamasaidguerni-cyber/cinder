interface Props {
  size?: number
  className?: string
}

export function Logo({ size = 36, className }: Props) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      className={className}
      aria-label="CINDER logo"
    >
      <defs>
        <linearGradient id="cinder-shield" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#f43f5e" />
          <stop offset="1" stopColor="#b91c1c" />
        </linearGradient>
      </defs>
      <path
        d="M32 3 57 12 V32 C57 46 46 56 32 61 C18 56 7 46 7 32 V12 Z"
        fill="#0b1117"
        stroke="url(#cinder-shield)"
        strokeWidth="3"
      />
      <path
        d="M43.31 45.31 A16 16 0 0 1 32 50 A16 16 0 0 1 32 18 A16 16 0 0 1 43.31 22.69"
        fill="none"
        stroke="#e5e7eb"
        strokeWidth="5.5"
        strokeLinecap="round"
      />
      <path
        d="M43.31 45.31 H52.5 M43.31 22.69 H52.5"
        fill="none"
        stroke="url(#cinder-shield)"
        strokeWidth="3"
        strokeLinecap="round"
      />
      <circle cx="54" cy="45.31" r="2.2" fill="#f43f5e" />
      <circle cx="54" cy="22.69" r="2.2" fill="#f43f5e" />
    </svg>
  )
}