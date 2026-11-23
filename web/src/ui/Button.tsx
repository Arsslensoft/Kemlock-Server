import { Button as AriaButton, type ButtonProps } from 'react-aria-components';

export interface Props extends Omit<ButtonProps, 'className'> {
  variant?: 'default' | 'primary' | 'danger';
  size?: 'small' | 'medium' | 'large';
  block?: boolean;
  className?: string;
}

/** The class names of a button, for links that look like one: `<Link className={buttonClass()}>`. */
export function buttonClass({
  variant = 'default',
  size = 'medium',
  block = false,
  className,
}: Pick<Props, 'variant' | 'size' | 'block' | 'className'> = {}): string {
  return [
    'btn',
    variant === 'primary' ? 'p' : variant === 'danger' ? 'd' : '',
    size === 'small' ? 's' : size === 'large' ? 'lg' : '',
    block ? 'block' : '',
    className ?? '',
  ]
    .filter(Boolean)
    .join(' ');
}

export function Button({ variant, size, block, className, ...rest }: Props) {
  return <AriaButton {...rest} className={buttonClass({ variant, size, block, className })} />;
}

/** A square button holding only an icon: always give it an aria-label. */
export function IconButton({ className, ...rest }: Omit<ButtonProps, 'className'> & { className?: string }) {
  return <AriaButton {...rest} className={className ? `ib ${className}` : 'ib'} />;
}
