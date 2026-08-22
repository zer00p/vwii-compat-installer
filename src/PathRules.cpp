#include "PathRules.h"
#include "FSAUtils.h"
#include "uid_sys.h"
#include "title.h"
#include "EndianUtils.h"
#include "log.h"

#include <memory>
#include <unordered_map>
#include <cstring>
#include <cstdlib>
#include <cstdio>

static const PathRuleDef GLOBAL_PATH_RULES[] = {
    // Root and system directories
    {"/sys",                                      0660, RuleUid::ROOT,        RuleGid::ROOT,    "System root directory"},
    {"/title",                                    0664, RuleUid::ROOT,        RuleGid::ROOT,    "Title root directory"},
    {"/ticket",                                   0660, RuleUid::ROOT,        RuleGid::ROOT,    "Ticket root directory"},
    {"/shared1",                                  0660, RuleUid::ROOT,        RuleGid::ROOT,    "Shared1 content directory"},
    {"/shared2",                                  0666, RuleUid::ROOT,        RuleGid::ROOT,    "Shared2 directory"},
    {"/tmp",                                      0666, RuleUid::ROOT,        RuleGid::ROOT,    "Temp directory"},
    {"/import",                                   0660, RuleUid::ROOT,        RuleGid::ROOT,    "Import directory"},
    {"/meta",                                     0660, RuleUid::ROOT,        RuleGid::ROOT,    "Meta directory"},

    // /sys files
    {"/sys/cert.sys",                             0664, RuleUid::ROOT,        RuleGid::ROOT,    "Certificate trust store"},
    {"/sys/uid.sys",                              0660, RuleUid::ROOT,        RuleGid::ROOT,    "Title UID table"},
    {"/sys/space.sys",                            0660, RuleUid::ROOT,        RuleGid::ROOT,    "Space allocation table"},
    {"/sys/*",                                    0660, RuleUid::ROOT,        RuleGid::ROOT,    "System configuration file"},

    // /shared1 files
    {"/shared1/content.map",                      0660, RuleUid::ROOT,        RuleGid::ROOT,    "Shared content hash map"},
    {"/shared1/*",                                0660, RuleUid::ROOT,        RuleGid::ROOT,    "Shared content binary"},

    // /shared2 contents (all 0666)
    {"/shared2/*",                                0666, RuleUid::ROOT,        RuleGid::ROOT,    "Shared2 item"},
    {"/shared2/*/*",                              0666, RuleUid::ROOT,        RuleGid::ROOT,    "Shared2 nested item"},
    {"/shared2/*/*/*",                            0666, RuleUid::ROOT,        RuleGid::ROOT,    "Shared2 deep item"},

    // /ticket contents
    {"/ticket/*",                                 0000, RuleUid::ROOT,        RuleGid::ROOT,    "Ticket category directory"},
    {"/ticket/*/*",                               0660, RuleUid::ROOT,        RuleGid::ROOT,    "Title ticket"},

    // /title category & title dirs
    {"/title/*",                                  0664, RuleUid::ROOT,        RuleGid::ROOT,    "Title category directory"},
    {"/title/*/*",                                0664, RuleUid::ROOT,        RuleGid::ROOT,    "Title directory"},

    // /title/<idHi>/<idLo>/content
    {"/title/*/*/content",                        0660, RuleUid::ROOT,        RuleGid::ROOT,    "Title content directory"},
    {"/title/*/*/content/*",                      0660, RuleUid::ROOT,        RuleGid::ROOT,    "Title content / TMD file"},

    // System Menu specific data
    {"/title/00000001/00000002/data/setting.txt", 0444, RuleUid::SYSTEM_MENU, RuleGid::SYSTEM_MENU, "System Menu setting.txt"},
    {"/title/00000001/00000002/data",             0600, RuleUid::SYSTEM_MENU, RuleGid::SYSTEM_MENU, "System Menu data directory"},

    // General title data & save directories (dynamic UID & GID)
    {"/title/*/*/data",                           0600, RuleUid::DYNAMIC,     RuleGid::DYNAMIC, "Title save data directory"},
    {"/title/*/*/data/*",                         0600, RuleUid::DYNAMIC,     RuleGid::DYNAMIC, "Title save data item"},
    {"/title/*/*/data/*/*",                       0600, RuleUid::DYNAMIC,     RuleGid::DYNAMIC, "Title save data nested item"},
};

struct TrieNode {
    std::string segment;
    const PathRuleDef* rule = nullptr;
    std::unordered_map<std::string, std::unique_ptr<TrieNode>> exactChildren;
    std::unique_ptr<TrieNode> wildcardChild;
};

static TrieNode g_rootNode;
static bool g_initialized = false;

static std::vector<std::string> SplitPathSegments(std::string_view path) {
    if (path.starts_with(VWII_MOUNT_POINT)) {
        path = path.substr(VWII_MOUNT_POINT.size());
    }
    std::vector<std::string> segments;
    size_t start = 0;
    while (start < path.size()) {
        while (start < path.size() && path[start] == '/') {
            start++;
        }
        if (start >= path.size()) break;
        size_t end = path.find('/', start);
        if (end == std::string_view::npos) {
            end = path.size();
        }
        segments.emplace_back(path.substr(start, end - start));
        start = end;
    }
    return segments;
}

static void InsertRule(TrieNode& root, const PathRuleDef& rule) {
    std::vector<std::string> segments = SplitPathSegments(rule.pattern);
    TrieNode* current = &root;
    for (const auto& seg : segments) {
        if (seg == "*") {
            if (!current->wildcardChild) {
                current->wildcardChild = std::make_unique<TrieNode>();
                current->wildcardChild->segment = "*";
            }
            current = current->wildcardChild.get();
        } else {
            auto& child = current->exactChildren[seg];
            if (!child) {
                child = std::make_unique<TrieNode>();
                child->segment = seg;
            }
            current = child.get();
        }
    }
    current->rule = &rule;
}

void PathRules_Init() {
    if (g_initialized) return;
    for (const auto& rule : GLOBAL_PATH_RULES) {
        InsertRule(g_rootNode, rule);
    }
    g_initialized = true;
}

static const PathRuleDef* FindRule(const TrieNode* node, size_t segIdx,
                                   const std::vector<std::string>& segments,
                                   uint64_t& outTitleId) {
    if (!node) return nullptr;

    if (segIdx == 3 && segments.size() >= 3 && segments[0] == "title") {
        char* end1 = nullptr;
        char* end2 = nullptr;
        uint32_t idHi = strtoul(segments[1].c_str(), &end1, 16);
        uint32_t idLo = strtoul(segments[2].c_str(), &end2, 16);
        if (end1 && *end1 == '\0' && end2 && *end2 == '\0' && segments[1].length() == 8 && segments[2].length() == 8) {
            outTitleId = ((uint64_t)idHi << 32) | idLo;
        }
    }

    if (segIdx == segments.size()) {
        return node->rule;
    }

    const std::string& seg = segments[segIdx];

    // 1. Try exact child first
    auto it = node->exactChildren.find(seg);
    if (it != node->exactChildren.end()) {
        const PathRuleDef* r = FindRule(it->second.get(), segIdx + 1, segments, outTitleId);
        if (r) return r;
    }

    // 2. Try wildcard child (*)
    if (node->wildcardChild) {
        const PathRuleDef* r = FindRule(node->wildcardChild.get(), segIdx + 1, segments, outTitleId);
        if (r) return r;
    }

    return nullptr;
}

static uint16_t ReadTmdGroupIdFromDisk(FSAClientHandle fsaClient, uint64_t titleId) {
    if (!fsaClient || !titleId) return 0;
    uint32_t idHi = (uint32_t)(titleId >> 32);
    uint32_t idLo = (uint32_t)(titleId & 0xFFFFFFFF);
    char path[128];
    snprintf(path, sizeof(path), "/vol/slccmpt01/title/%08x/%08x/content/title.tmd", idHi, idLo);

    FSAFileHandle fd = 0;
    if (FSAOpenFileEx(fsaClient, path, "rb", (FSMode)0660, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        return 0;
    }

    alignas(0x40) TitleTmd tmdHeader;
    int readRes = FSAReadFile(fsaClient, &tmdHeader, sizeof(TitleTmd), 1, fd, 0);
    FSACloseFile(fsaClient, fd);

    if (readRes > 0) {
        return FromBE16(tmdHeader.groupId);
    }
    return 0;
}

ResolvedPathRule PathRules_Resolve(FSAClientHandle fsaClient, std::string_view path, uint16_t tmdGroupId) {
    PathRules_Init();

    std::vector<std::string> segments = SplitPathSegments(path);
    uint64_t titleId = 0;
    const PathRuleDef* rule = FindRule(&g_rootNode, 0, segments, titleId);

    ResolvedPathRule resolved;
    if (rule) {
        resolved.matched = true;
        resolved.pattern = rule->pattern;
        resolved.mode = (FSMode)rule->mode;
        resolved.titleId = titleId;
        resolved.description = rule->description;

        // Resolve UID
        if (rule->uid == RuleUid::DYNAMIC) {
            if (titleId == VWII_TITLE_ID_SYSTEM_MENU) {
                resolved.uid = (uint32_t)RuleUid::SYSTEM_MENU;
            } else if (fsaClient != 0 && titleId != 0) {
                resolved.uid = UID_GetOrCreate(fsaClient, titleId);
            } else {
                resolved.uid = 0;
            }
        } else {
            resolved.uid = (uint32_t)rule->uid;
        }

        // Resolve GID
        if (rule->gid == RuleGid::DYNAMIC) {
            if (tmdGroupId != 0) {
                resolved.gid = tmdGroupId;
            } else if (titleId == VWII_TITLE_ID_SYSTEM_MENU) {
                resolved.gid = (uint16_t)RuleGid::SYSTEM_MENU;
            } else if (fsaClient != 0 && titleId != 0) {
                resolved.gid = ReadTmdGroupIdFromDisk(fsaClient, titleId);
            } else {
                resolved.gid = 0;
            }
        } else {
            resolved.gid = (uint16_t)rule->gid;
        }
    } else {
        // Fallback defaults
        resolved.matched = false;
        resolved.pattern = "";
        resolved.titleId = titleId;
        resolved.mode = (FSMode)0660;
        resolved.uid = 0;
        resolved.gid = 0;
        resolved.description = "Default";
    }

    return resolved;
}

bool PathRules_CheckPermissions(FSAClientHandle fsaClient, std::string_view path, const FSStat& stat,
                                ResolvedPathRule* outExpectedRule, uint16_t tmdGroupId) {
    ResolvedPathRule expected = PathRules_Resolve(fsaClient, path, tmdGroupId);
    if (outExpectedRule) {
        *outExpectedRule = expected;
    }
    return FSA_IsPermissionAcceptable(stat, expected.mode, expected.uid, expected.gid);
}

std::vector<ResolvedPathRule> PathRules_GetStockRootDirs() {
    static const char* const rootDirs[] = {
        "/sys", "/title", "/ticket", "/shared1", "/shared2", "/tmp", "/import"
    };
    std::vector<ResolvedPathRule> result;
    for (const char* r : rootDirs) {
        result.push_back(PathRules_Resolve(r));
    }
    return result;
}
