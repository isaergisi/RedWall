export const Unsafe = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />; // expect: RW-JS-XSS
export const Fixed = () => <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;
