// TODO: right now we support only X.X.X[-bX], in the future we might want to support more complex
// idea: for anything else versions have to match exactly? but whatever we do, update both version
// parsing in both FE, BE and build script!

const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)(?:-b(\d+))?$/;

type ParsedVersion = [number, number, number, number];

export function parseVersion(v: string): ParsedVersion {
    const m = VERSION_RE.exec(v.trim());
    if (!m) {
        return [-999, -999, -999, -Infinity];
    }
    const [, major, minor, patch, beta] = m;
    const betaRank = beta !== undefined ? parseInt(beta, 10) : Infinity;
    return [parseInt(major, 10), parseInt(minor, 10), parseInt(patch, 10), betaRank];
}

function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
    for (let i = 0; i < a.length; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

export function isRobotOutdated(installedWith: string, MINIMUM_INSTALLER_VERSION: string): boolean {
    if (installedWith.includes("dev")) return false; // If you are messing with dev versions, I expect you to know what you are doing!
    return (compareVersions(parseVersion(installedWith), parseVersion(MINIMUM_INSTALLER_VERSION)) < 0
    );
}